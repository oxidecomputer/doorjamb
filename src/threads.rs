use std::{
    ffi::CString,
    os::fd::AsRawFd,
    sync::{Arc, Condvar, Mutex, OnceLock, Weak},
    cell::RefCell,
};

use crate::server::{rust_doors_server_proc, DoorInner, ServerState};
use crate::sys;
use crate::upanic::*;
use libc::{c_uint, c_void};

thread_local! {
    static DOOR_SERVER_THREAD: RefCell<*const ServerThread> = const {
        RefCell::new(std::ptr::null())
    };
}

#[derive(Debug)]
pub(crate) struct ServerThread {
    pub(crate) locked: Mutex<ServerThreadLocked>,
    pub(crate) cv: Condvar,
}

#[derive(Debug)]
pub(crate) struct ServerThreadLocked {
    pub(crate) thread_id: Option<c_uint>,
    pub(crate) state: ServerThreadState,
    pub(crate) door: Option<Weak<DoorInner>>,
    pub(crate) shutdown: bool,
}

#[derive(Debug)]
pub(crate) enum ServerThreadState {
    Created,
    Bound,
    Exited,
}

/*
 * Return an immutable reference to the per-thread object.  This reference is
 * valid until the object is torn down in rust_door_thread_exit().
 */
pub fn borrow_thread_local() -> &'static ServerThread {
    let st = DOOR_SERVER_THREAD.with(|st| *st.borrow());

    if st.is_null() {
        upanic("per-thread object was not present");
    } else {
        unsafe { &*st }
    }
}

static ORIGINAL_CREATE_PROC: OnceLock<Option<sys::CreateProcFn>> =
    OnceLock::new();

pub fn install_create_proc() {
    /*
     * Install our door thread creation procedure, stashing the original one so
     * that we can chain calls to it for doors that do not belong to us.
     */
    ORIGINAL_CREATE_PROC.get_or_init(|| unsafe {
        sys::door_server_create(rust_door_create_proc)
    });
}

#[no_mangle]
extern "C" fn rust_door_create_proc(infop: *mut sys::DoorInfo) {
    /*
     * Make sure this door is one created with DOOR_PRIVATE; i.e., that we were
     * passed a door_info_t:
     */
    let Some(info) = (unsafe { infop.as_ref() }) else {
        return rust_door_create_proc_fallback(infop);
    };

    /*
     * Confirm that the door server procedure is our wrapper:
     */
    if (info.di_attributes & sys::DOOR_PRIVATE) == 0
        || info.di_proc != (rust_doors_server_proc as *mut c_void)
    {
        return rust_door_create_proc_fallback(infop);
    }

    /*
     * From this point forward, we are confident that we own the door and there
     * should be no chaining to other thread creation functions.
     *
     * Allow the rest of this routine to use panic!() if needed.  We'll promote
     * that panic to a upanic().
     */
    let res = std::panic::catch_unwind(|| {
        /*
         * It should be safe to use the reference to our inner door object here
         * in the thread creation callback.  This callback is only called with
         * our cookie value during a door_call(3C) or a door_return(3C).  In the
         * DOOR_PRIVATE model we have control of when both of those calls occur:
         * either initially during our constructor, or within one of our managed
         * threads created below.
         */
        let (weak_di, di) = {
            let di = unsafe { Arc::from_raw(info.di_data as *const DoorInner) };
            (Arc::downgrade(&di), unsafe { &*Arc::into_raw(di) })
        };

        let st = Arc::new(ServerThread {
            locked: Mutex::new(ServerThreadLocked {
                thread_id: None,
                state: ServerThreadState::Created,
                door: Some(weak_di),
                shutdown: false,
            }),
            cv: Default::default(),
        });

        /*
         * Make sure we are still supposed to be creating threads, and if so,
         * register this one.  Registration needs to occur prior to creating the
         * thread so that we don't end up racing with a revocation.
         */
        {
            let mut locked = di.locked.lock().unwrap();

            match locked.state {
                ServerState::Created => (),
                ServerState::Stopping => {
                    return;
                }
                ServerState::Stopped => {
                    panic!("thread creation after door server stopped?");
                }
            }

            locked.threads.push(Arc::clone(&st));
        }

        /*
         * Create a thread and pass the door data to it.
         */
        let arg = Arc::into_raw(Arc::clone(&st));

        let mut tid: c_uint = 0;
        let r = unsafe {
            sys::thr_create(
                std::ptr::null_mut(),
                0,
                rust_door_thread,
                arg as *mut c_void,
                sys::THR_DETACHED,
                &mut tid,
            )
        };

        if r == 0 {
            /*
             * Stash the thread ID in the server thread object for debugging
             * purposes:
             */
            st.locked.lock().unwrap().thread_id = Some(tid);
            st.cv.notify_all();

            /*
             * Thread creation was successful.  Attempt to set the name for
             * diagnostic purposes.
             */
            let name =
                CString::new(format!("doorserver-{:x}", info.di_data as usize))
                    .unwrap();
            unsafe { sys::thr_setname(tid, name.as_ptr()) };

            /*
             * Yield to allow it to begin running, like the default
             * implementation in libc does.
             */
            std::thread::yield_now();
            return;
        }

        /*
         * Thread creation was not successful so we'll need to take the
         * reference back so that we can drop it.
         */
        let _ = unsafe { Arc::from_raw(arg) };

        /*
         * XXX error channel?
         */
        let e = std::io::Error::from_raw_os_error(r);
        eprintln!("WARNING: door thread creation failed: {e}"); /* XXX */
    });

    upanic_if_unwound("panic in door thread creation", res);
}

#[no_mangle]
extern "C" fn rust_door_create_proc_fallback(infop: *mut sys::DoorInfo) {
    /*
     * Delegate to the original server thread creation routine if one
     * existed when we registered ours
     */
    if let Some(Some(create_proc)) = ORIGINAL_CREATE_PROC.get() {
        create_proc(infop);
    }
}

#[no_mangle]
extern "C" fn rust_door_thread(arg: *mut c_void) -> *mut c_void {
    let res = std::panic::catch_unwind(|| {
        /*
         * When this thread was created, rust_door_create_proc() passed us a raw
         * pointer created from a Arc<ServerThread>.  We do not convert it back
         * to an Arc here because we do not wish to accidentally drop it.  This
         * function may or may not return all the way, depending on what happens
         * in door calls serviced on this thread.
         *
         * Most of the heavy lifting occurs in this inner function so that we
         * can use Rust facilities that might panic, and so that drop calls
         * occur naturally for things like mutex guards before we end up back
         * here.
         */
        if !rust_door_thread_impl(arg as *const ServerThread) {
            /*
             * We didn't get all the way off the ground.  Return through the
             * cleanup path.
             */
            return rust_door_thread_exit();
        }

        /*
         * Calling door_return(3C) with all zero values informs the OS that this
         * thread is ready to service door calls.  This call should not return.
         */
        let r = unsafe {
            sys::door_return(std::ptr::null_mut(), 0, std::ptr::null_mut(), 0)
        };
        let e = unsafe { *libc::___errno() };
        upanic(format!("back from door return (r {r} e {e})"));
    });

    upanic_if_unwound("door thread panic", res);

    /*
     * Door server threads are detached, so their return value is always
     * meaningless.
     */
    std::ptr::null_mut()
}

#[no_mangle]
fn rust_door_thread_impl(st: *const ServerThread) -> bool {
    /*
     * Stash the door info pointer in our thread local so that we can find it
     * later.  We consider the reference parked here, and thus safe to use from
     * the raw pointer until we get to rust_door_thread_exit() where it will be
     * reconstituted from the thread local and dropped.
     */
    assert!(DOOR_SERVER_THREAD.replace(st).is_null());
    let st = unsafe { &*st };

    /*
     * Wait for the file descriptor to be stored in the object after door
     * creation completes.  At least one thread appears to be created
     * immediately during the door_create(3C) call, so we need to be careful not
     * to race.
     */
    let fd = {
        /*
         * The per-thread object contains a weak reference to the per-door
         * object.  Upgrade that reference so we can interact with it here:
         */
        let di = {
            let locked = st.locked.lock().unwrap();

            if locked.shutdown {
                /*
                 * Our shutdown has been requested, just give up now.
                 */
                return false;
            }

            if let Some(di) = locked.door.as_ref().and_then(|di| di.upgrade()) {
                di
            } else {
                /*
                 * If the inner door object no longer exists, just bail out.
                 */
                return false;
            }
        };

        let fd = {
            let mut locked = di.locked.lock().unwrap();

            loop {
                match locked.state {
                    ServerState::Created => (),
                    ServerState::Stopping => {
                        /*
                         * This door is being shut down, so we don't want to
                         * create any more threads.
                         */
                        return false;
                    }
                    ServerState::Stopped => {
                        panic!("door thread create after door server stopped?");
                    }
                }

                if let Some(fd) = locked.fd.as_ref() {
                    break fd.as_raw_fd();
                } else {
                    locked = di.cv.wait(locked).unwrap();
                }
            }
        };

        fd
    };

    /*
     * We do not wish to experience the ills of cancellation(7).
     */
    unsafe {
        sys::pthread_setcancelstate(
            sys::PTHREAD_CANCEL_DISABLE,
            std::ptr::null_mut(),
        )
    };

    /*
     * We only want to service door calls for the particular private pool we've
     * created, not the global pool.
     */
    if unsafe { sys::door_bind(fd) } == -1 {
        return false;
    }

    /*
     * Announce that we have succesfully bound this thread to the private pool
     * for the door.
     */
    {
        let mut locked = st.locked.lock().unwrap();
        assert!(matches!(locked.state, ServerThreadState::Created));
        locked.state = ServerThreadState::Bound;
        st.cv.notify_all();
    }

    true
}

#[no_mangle]
pub fn rust_door_thread_exit() {
    /*
     * Take the thread-local door inner pointer and replace it with NULL.
     */
    let st = DOOR_SERVER_THREAD.with(|st| st.replace(std::ptr::null()));

    /*
     * Recover our ServerThread reference so that we can drop it on return from
     * this function as we are bringing down the thread.
     */
    let st: Arc<ServerThread> = if st.is_null() {
        /*
         * This is very bad.  Our thread local should have been established very
         * early in door thread startup.
         */
        upanic("per-thread object was not present");
    } else {
        unsafe { Arc::from_raw(st) }
    };

    /*
     * Inform waiters that we are exiting.  Drop our reference to the door
     * object, weak though it is.
     */
    let mut locked = st.locked.lock().unwrap();
    locked.state = ServerThreadState::Exited;
    locked.door.take();
    st.cv.notify_all();
}
