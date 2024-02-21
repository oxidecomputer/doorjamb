#![allow(unused_imports)]

use std::{
    cell::RefCell,
    ffi::CString,
    fs::File,
    io::ErrorKind,
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::prelude::OsStrExt,
    },
    panic::RefUnwindSafe,
    path::Path,
    sync::{Arc, Condvar, Mutex, Weak},
    thread::JoinHandle,
    time::Duration,
};

use anyhow::{anyhow, bail, Result};
use libc::{c_char, c_int, c_uint, c_void, size_t};
use once_cell::sync::OnceCell;

//static REGISTRY: OnceCell<Registry> = OnceCell::new();
static ORIGINAL_CREATE_PROC: OnceCell<sys::CreateProcFn> = OnceCell::new();

//#[derive(Default)]
//struct Registry {
//    cookies: Mutex<Vec<Arc<DoorInner>>>,
//}

thread_local! {
    static DOOR_SERVER_THREAD: RefCell<*const ServerThread> = const {
        RefCell::new(std::ptr::null())
    };
}

#[derive(Debug)]
struct ServerThread {
    locked: Mutex<ServerThreadLocked>,
    cv: Condvar,
}

#[derive(Debug)]
struct ServerThreadLocked {
    thread_id: Option<c_uint>,
    state: ServerThreadState,
    door: Option<Weak<DoorInner>>,
    shutdown: bool,
}

#[derive(Debug)]
enum ServerThreadState {
    Created,
    Bound,
    Exited,
}

// impl Registry {
//     /**
//      * Obtain a reference to the global registry for all door servers created by
//      * this library.
//      */
//     fn obtain() -> &'static Registry {
//         /*
//          * Install our door thread creation procedure, stashing the original one
//          * so that we can chain calls to it for doors that do not belong to us.
//          */
//         ORIGINAL_CREATE_PROC.get_or_init(|| unsafe {
//             sys::door_server_create(rust_door_create_proc)
//         });
//
//         REGISTRY.get_or_init(|| Registry::default())
//     }
//
//     fn unregister(&self, di: &Arc<DoorInner>) {
//         let mut cookies = self.cookies.lock().unwrap();
//
//         let mut found = false;
//         while let Some(i) =
//             cookies.iter().position(|c| Arc::as_ptr(c) == Arc::as_ptr(di))
//         {
//             /*
//              * Make sure there are no active server threads and that there will
//              * be no new threads in future.
//              */
//             {
//                 let locked = cookies[i].locked.lock().unwrap();
//                 if !locked.threads.is_empty() {
//                     panic!("unregister door that still has threads");
//                 }
//             }
//
//             cookies.swap_remove(i);
//             found = true;
//         }
//
//         if !found {
//             eprintln!("WARNING: unregister found nothing");
//         }
//     }
//
//     fn register(&self, di: &Arc<DoorInner>) -> *mut c_void {
//         let mut cookies = self.cookies.lock().unwrap();
//
//         /*
//          * Make sure this door object is not already registered.
//          */
//         for c in cookies.iter() {
//             if Arc::as_ptr(c) == Arc::as_ptr(di) {
//                 panic!("double registration?");
//             }
//         }
//
//         /*
//          * Take a hold on the inner door object that we use for the cookie
//          * pointer.  This will prevent it from being freed until we revoke it.
//          */
//         cookies.push(Arc::clone(&di));
//
//         /*
//          * Return the inner door object address to use as the cookie.  This
//          * pointer will be valid until the object is removed by a subsequent
//          * unregister() call, which will remove our reference to it.  Server
//          * threads and other consumers must take their own references.
//          */
//         Arc::as_ptr(di) as *mut c_void
//     }
//
//     fn locate(&self, cookie: *mut c_void) -> Option<Arc<DoorInner>> {
//         if cookie.is_null() {
//             return None;
//         }
//
//         let cookies = self.cookies.lock().unwrap();
//
//         for c in cookies.iter() {
//             if Arc::as_ptr(c) == (cookie as *const DoorInner) {
//                 let di = Arc::clone(&c);
//                 assert_eq!(Arc::as_ptr(&di) as *mut c_void, cookie);
//                 return Some(Arc::clone(&c));
//             }
//         }
//
//         None
//     }
// }

#[allow(unused)]
mod sys;

#[derive(Debug)]
struct Arg {}

struct Door {
    inner: Arc<DoorInner>,
}

enum ServerState {
    Created,
    Stopping,
    Stopped,
}

struct DoorInner {
    func: Box<dyn DoorFuncBoxCall>,

    cv: Condvar,
    locked: Mutex<DoorLocked>,
}

struct DoorLocked {
    fd: Option<c_int>,
    unref: bool,
    state: ServerState,
    threads: Vec<Arc<ServerThread>>,
}

struct DoorFuncBox<F> {
    func: F,
}

trait DoorFuncBoxCall: Sync + Send + RefUnwindSafe {
    fn call(&self, a: Arg);
}

impl<F> DoorFuncBoxCall for DoorFuncBox<F>
where
    F: Sync + Send + Fn(Arg) + RefUnwindSafe,
{
    fn call(&self, a: Arg) {
        (self.func)(a);
    }
}

impl Drop for DoorInner {
    fn drop(&mut self) {
        let locked = self.locked.get_mut().unwrap();
        if let Some(fd) = locked.fd {
            panic!("door server: inner object dropped with open fd {fd}");
        }

        if !locked.threads.is_empty() {
            panic!(
                "door server: inner object dropped with threads: {:?}",
                locked.threads
            );
        }

        println!("door inner object dropped");
    }
}

#[no_mangle]
extern "C" fn rust_door_create_proc(infop: *mut sys::DoorInfo) {
    println!("rust_door_create_proc(0x{:x})", infop as usize);

    /*
     * Make sure this door is one created with DOOR_PRIVATE; i.e., that we were
     * passed a door_info_t:
     */
    let info = unsafe { infop.as_ref() };
    let Some(info) = info else {
        if let Some(create_proc) = ORIGINAL_CREATE_PROC.get() {
            /*
             * Delegate to the original server thread creation routine if one
             * existed when we registered ours:
             */
            create_proc(infop);
        }
        return;
    };

    println!("rust_door_create_proc({info:#?})");

    /*
     * Confirm that the door server procedure is our wrapper:
     */
    if (info.di_attributes & sys::DOOR_PRIVATE) == 0
        || info.di_proc != (rust_doors_server_proc as *mut c_void)
    {
        println!("rust_door_create_proc({info:#?}): not our wrapper?");
        if let Some(create_proc) = ORIGINAL_CREATE_PROC.get() {
            create_proc(infop);
        }
        return;
    }

    /*
     * From this point forward, we are confident that we own the door and there
     * should be no chaining to other thread creation functions.
     *
     * It should be safe to use the reference to our inner door object here in
     * the thread creation callback.  This callback is only called with our
     * cookie value during a door_call(3C) or a door_return(3C).  In the
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
                println!("DCP: door is stopping; NO MORE THREADS!");
                return;
            }
            ServerState::Stopped => {
                panic!("DCP: thread creation after door server stopped?");
            }
        }

        locked.threads.push(Arc::clone(&st));
    }

    println!("DCP: creating a door thread for {:x} ...", info.di_data as usize);

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
         * Yield to allow it to begin running, like the default implementation
         * in libc does.
         */
        std::thread::yield_now();
        return;
    }

    /*
     * Thread creation was not successful so we'll need to take the reference
     * back so that we can drop it.
     */
    let _ = unsafe { Arc::from_raw(arg) };

    let e = std::io::Error::from_raw_os_error(r);
    eprintln!("WARNING: door thread creation failed: {e}"); /* XXX */
}

#[no_mangle]
extern "C" fn rust_door_thread_exit() -> *mut c_void {
    let tid = unsafe { sys::thr_self() };

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
         * XXX This is very bad.  Our thread local should have been established
         * very early in door thread startup.
         */
        eprintln!("[{tid}] NO SERVER THREAD; ABORT");
        std::process::abort();
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

    println!("[{tid}] DOOR THREAD EXIT");

    /*
     * Door server threads are detached, so their return value is always
     * meaningless.
     */
    std::ptr::null_mut()
}

#[no_mangle]
extern "C" fn rust_door_thread(arg: *mut c_void) -> *mut c_void {
    let tid = unsafe { sys::thr_self() };

    println!("[{tid}] door thread starting");

    /*
     * When this thread was created, rust_door_create_proc() passed us a raw
     * pointer created from a Arc<ServerThread>.  We do not convert it back to
     * an Arc here because we do not wish to accidentally drop it.  This
     * function may or may not return all the way, depending on what happens in
     * door calls serviced on this thread.
     */
    let st = arg as *const ServerThread;

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
            let mut locked = st.locked.lock().unwrap();

            if locked.shutdown {
                /*
                 * Our shutdown has been requested, just give up now.
                 */
                drop(locked);
                return rust_door_thread_exit();
            }

            if let Some(di) = locked.door.as_ref().and_then(|di| di.upgrade()) {
                di
            } else {
                /*
                 * If the inner door object no longer exists, just bail out.
                 */
                drop(locked);
                return rust_door_thread_exit();
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
                        drop(locked);
                        return rust_door_thread_exit();
                    }
                    ServerState::Stopped => {
                        panic!("blah");
                    }
                }

                if let Some(fd) = locked.fd {
                    break fd;
                } else {
                    locked = di.cv.wait(locked).unwrap();
                }
            }
        };

        println!(
            "[{tid}] door thread for {:x}, fd {fd}",
            std::ptr::addr_of!(di) as usize,
        );

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
        return rust_door_thread_exit();
    }

    {
        let mut locked = st.locked.lock().unwrap();
        assert!(matches!(locked.state, ServerThreadState::Created));
        locked.state = ServerThreadState::Bound;
        st.cv.notify_all();
    }

    /*
     * Calling door_return(3C) with all zero values informs the OS that this
     * thread is ready to service door calls.  This call should not return.
     */
    let r = unsafe {
        sys::door_return(std::ptr::null_mut(), 0, std::ptr::null_mut(), 0)
    };
    let e = unsafe { *libc::___errno() };

    /*
     * XXX upanic here
     */
    eprintln!("[{tid}] OH NO, back from door return?! (r {r} e {e})");
    std::process::abort();
}

#[no_mangle]
extern "C" fn rust_doors_server_proc(
    cookie: *mut c_void,
    argp: *mut c_char,
    arg_size: size_t,
    dp: *mut sys::door_desc_t,
    n_desc: c_uint,
) {
    let tid = unsafe { sys::thr_self() };

    /*
     * Fish our per-thread object out of thread local storage, without creating
     * a new reference.
     */
    let st: &ServerThread = {
        let st = DOOR_SERVER_THREAD.with(|st| *st.borrow());
        unsafe { &*st }
    };

    /*
     * The registry holds a reference to the per-door object and will refuse to
     * drop it until all server threads have exited and more cannot be created.
     */
    let di = cookie as *const DoorInner;

    /*
     * Do some consistency checks between the per-thread object in our thread
     * local storage and the per-door object we've been passed as the cookie.
     */
    {
        let locked = st.locked.lock().unwrap();
        if locked.shutdown {
            /*
             * We're being torn down; don't look at anything else.
             */
            drop(locked);
            rust_door_thread_exit();
            return;
        }

        if let Some(door) = locked.door.as_ref() {
            if door.as_ptr() != di {
                /*
                 * XXX upanic
                 */
                eprintln!(
                    "[{tid}] INCONSISTENT {:x} != {:x}!",
                    door.as_ptr() as usize,
                    di as usize
                );
                std::process::abort();
            }
        }
    }

    let di = unsafe { &*di };

    /*
     * Because we created the door with DOOR_UNREF, if the door becomes
     * unreferenced we'll get a special invocation with the magic
     * DOOR_UNREF_DATA argument.  This can happen if the door path is detached
     * with an fdetach(3C) call or the fdetach program.  Note that it does not
     * imply that there will be no further door calls.
     */
    if argp == sys::DOOR_UNREF_DATA {
        println!("[{tid}] DOOR HAS BECOME UNREF!");

        di.locked.lock().unwrap().unref = true;
        di.cv.notify_all();

        rust_door_thread_exit();
        return;
    }

    println!("[{tid}] calling door func()...");
    let res = std::panic::catch_unwind(|| {
        /*
         * The provided door function may panic and we want to be able to catch
         * that and deal with it accordingly.
         */
        (di.func).call(Arg {});
    });
    println!("[{tid}] back from door func(): {res:?}");

    if res.is_err() {
        eprintln!("[{tid}] DOOR FUNCTION PANIC: {res:?}");

        /*
         * If we return from this function, the thread will just exit.  The
         * client door_call(3C) invocation should fail with EINTR.
         */
        drop(res); /* XXX */
        rust_door_thread_exit();
        return;
    }

    drop(res); /* XXX */

    let r = unsafe {
        /*
         * NOTE: This call should not return.  This function must be careful not
         * to create anything that needs to be dropped to function correctly.
         */
        sys::door_return(std::ptr::null_mut(), 0, std::ptr::null_mut(), 0)
    };
    if r != -1 {
        /*
         * XXX Should upanic() here; this function should not return without an
         * error.
         */
        eprintln!("[{tid}] DOOR RETURN RETURNED ZERO");
        std::process::abort();
    }

    let e = unsafe { *libc::___errno() };
    eprintln!("[{tid}] DOOR RETURN FAILURE: e {e}");

    rust_door_thread_exit();
}

impl Door {
    fn new<F>(func: F) -> Result<Door>
    where
        F: Fn(Arg) + Send + Sync + RefUnwindSafe + 'static,
    {
        /*
         * Install our door thread creation procedure, stashing the original
         * one so that we can chain calls to it for doors that do not belong to
         * us.
         */
        ORIGINAL_CREATE_PROC.get_or_init(|| unsafe {
            sys::door_server_create(rust_door_create_proc)
        });

        /*
         * First, create our tracking object.  We need to do this prior to door
         * creation so that we can use its memory address as the cookie address
         * to pass to the door.
         */
        let d = Door {
            inner: Arc::new(DoorInner {
                func: Box::new(DoorFuncBox { func }),
                cv: Default::default(),
                locked: Mutex::new(DoorLocked {
                    fd: Default::default(),
                    unref: Default::default(),
                    state: ServerState::Created,
                    threads: Default::default(),
                }),
            }),
        };

        println!("REF 1: {}", Arc::strong_count(&d.inner));

        /*
         * We need to turn the inner object into a raw pointer that we can use
         * as a cookie value to pass to door_create(3C).  In the drop
         * implementation for Door, we'll abort the process if we cannot claw
         * the pointer back from the system before we drop our reference.
         */
        let cookie = Arc::as_ptr(&d.inner) as *mut c_void;

        println!("REF 2: {}", Arc::strong_count(&d.inner));

        /*
         * Create a door descriptor.
         */
        let fd = unsafe {
            sys::door_create(
                rust_doors_server_proc,
                cookie,
                /*
                 * We want to know when a door becomes unreferenced.  We don't
                 * want the client to send us any file descriptors.  We do not
                 * want threads to be cancelled.  Finally, let the door
                 * subsystem know that we will be creating our own door threads.
                 */
                sys::DOOR_UNREF
                    | sys::DOOR_REFUSE_DESC
                    | sys::DOOR_NO_CANCEL
                    | sys::DOOR_PRIVATE,
            )
        };
        if fd < 0 {
            let e = std::io::Error::last_os_error();
            let di = unsafe { Arc::from_raw(cookie) };
            bail!("could not create a door: {e}");
        }

        d.inner.locked.lock().unwrap().fd = Some(fd);
        d.inner.cv.notify_all();

        Ok(d)
    }

    fn door_fd(&self) -> c_int {
        self.inner.locked.lock().unwrap().fd.unwrap()
    }

    fn attach_impl(&self, path: &Path, force: bool) -> Result<()> {
        let cpath = CString::new(path.as_os_str().as_bytes()).unwrap();

        println!("REF 3: {}", Arc::strong_count(&self.inner));

        if force {
            /*
             * First, remove an existing door if there is one.  A previous door
             * left attached by a terminated process will cause us to fail EBUSY
             * when we reattach.
             */
            unsafe { sys::fdetach(cpath.as_ptr()) };
            match std::fs::remove_file(&path) {
                Ok(()) => (),
                Err(e) if e.kind() == ErrorKind::NotFound => (),
                Err(e) => bail!("removing {path:?}: {e}"),
            }
        }

        /*
         * Create a new, empty file at the point in the file system where we
         * need to attach the door.  We don't need to write anything, so we
         * don't need to keep the File around after creation.
         */
        std::fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&path)
            .map_err(|e| anyhow!("creating {path:?}: {e}"))?;

        let r = unsafe { sys::fattach(self.door_fd(), cpath.as_ptr()) };
        if r != 0 {
            let e = std::io::Error::last_os_error();
            bail!("unable to attach at {path:?}: {e}");
        }

        Ok(())
    }

    fn attach<P: AsRef<Path>>(&self, path: P) -> Result<()> {
        self.attach_impl(path.as_ref(), false)
    }

    fn force_attach<P: AsRef<Path>>(&self, path: P) -> Result<()> {
        self.attach_impl(path.as_ref(), true)
    }

    fn wait_for_unref(&self) {
        //println!("REF WFU E: {}", Arc::strong_count(&self.inner));

        let mut locked = self.inner.locked.lock().unwrap();
        while !locked.unref {
            locked = self.inner.cv.wait(locked).unwrap();
        }
        //println!("REF WFU R: {}", Arc::strong_count(&self.inner));
    }

    fn revoke(&self) -> Result<()> {
        /*
         * First, mark the per-door object so that no more threads will be
         * created.
         */
        let (fd, threads) = {
            let mut locked = self.inner.locked.lock().unwrap();

            loop {
                match locked.state {
                    ServerState::Created => {
                        /*
                         * We are the first on the scene; begin revocation!
                         */
                        break;
                    }
                    ServerState::Stopping => {
                        /*
                         * Someone beat us to it.  Wait for them to finish.
                         */
                        locked = self.inner.cv.wait(locked).unwrap();
                        continue;
                    }
                    ServerState::Stopped => {
                        /*
                         * The meal was cooked a long time ago.
                         */
                        return Ok(());
                    }
                }
            }

            println!("REVOKE: marking stopped...");
            locked.state = ServerState::Stopping;
            self.inner.cv.notify_all();

            /*
             * Inform all threads that we need to shut down.
             */
            for st in locked.threads.iter() {
                st.locked.lock().unwrap().shutdown = true;
                st.cv.notify_all();
            }

            (
                locked.fd,
                std::mem::replace(&mut locked.threads, Default::default()),
            )
        };

        let Some(fd) = fd else {
            /*
             * XXX
             */
            bail!("already closed?");
        };

        /*
         * Next, we need to shut down each thread that is parked waiting to
         * service a door call.  This is perhaps surprisingly intricate: a
         * thread parked in door_return() waiting to service a call will
         * unfortunately block forever, even if it is bound to a particular
         * private pool and the door for that pool has been revoked.  Even
         * though we have a list of thread IDs for all of our private pool
         * threads, we cannot use thr_kill(3C) to kick them out because the door
         * return logic always restarts on EINTR without returning to code that
         * we control.
         *
         * The only apparent way to kick these threads out is to make a door
         * call that wakes them up.  We can't control which thread will service
         * a particular invocation of door_call(3C), but if we keep calling it,
         * and have our service procedure merely exit because we've marked the
         * thread for shutdown, we'll eventually get them all.
         *
         * There is a wrinkle: though we continue to progress to the point where
         * the door is revoked, we are not there yet!  Calls could still come
         * from outside the process, because there is nothing to stop a process
         * from keeping a door descriptor open for a long time even though we
         * may have detached it from the file system.  A call to door_call(3C)
         * will block waiting for a thread, and if no such thread happens to
         * exist we will block forever -- or until the door is revoked.
         *
         * To avoid blocking this thread, we start _another_ thread whose sole
         * job is to make frenetic door calls until we have, here, determined
         * that there are no threads left to wake up.  At that time, we'll
         * revoke the door and then join our helper thread.  Note that we
         * cannot simply use the original file descriptor here, because
         * door_revoke(3C) will, as a side effect, close(2) the fd.
         */

        let other_fd = unsafe {
            libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, libc::STDERR_FILENO + 1)
        };
        if other_fd < 0 {
            let e = std::io::Error::last_os_error();
            bail!("could not dup door fd: {e}");
        }

        println!("REVOKE: starting helper...");
        let jh = std::thread::spawn(move || loop {
            println!("HELPER: make a the door call...");
            let mut arg = sys::DoorArg {
                data_ptr: std::ptr::null_mut(),
                data_size: 0,
                desc_ptr: std::ptr::null_mut(),
                desc_num: 0,
                rbuf: std::ptr::null_mut(),
                rsize: 0,
            };

            let r = unsafe { sys::door_call(other_fd, &mut arg) };
            let e = unsafe { *libc::___errno() };
            if r != 0 && e == libc::EBADF {
                /*
                 * door_call(3C) will fail with EBADF if the door has been
                 * revoked.  Unfortunately we cannot tell if this means we made
                 * a programming error with the file descriptor, and
                 * accidentally closed it before we meant to.
                 */
                assert_eq!(unsafe { libc::close(other_fd) }, 0);
                return;
            }

            /*
             * Whatever else happens, we need to go around again.
             */
            std::thread::yield_now();
        });

        loop {
            /*
             * Check to see if any threads are active.
             */
            let nactive = threads
                .iter()
                .filter(|st| {
                    !matches!(
                        st.locked.lock().unwrap().state,
                        ServerThreadState::Exited,
                    )
                })
                .count();

            println!("REVOKE: {nactive} still active");
            if nactive == 0 {
                break;
            }
        }

        let r = unsafe { sys::door_revoke(fd) };
        let e = unsafe { *libc::___errno() };
        if r != 0 {
            bail!("door_revoke failed -- r {r} e {e}");
        }

        println!("REVOKE: joining helper...");
        jh.join().unwrap();

        println!("REVOKE: ok!");
        let mut locked = self.inner.locked.lock().unwrap();
        assert!(locked.fd.take().is_some());
        locked.state = ServerState::Stopped;
        self.inner.cv.notify_all();

        Ok(())
    }
}

impl Drop for Door {
    fn drop(&mut self) {
        /*
         * NOTE: This revoke call is vital for correctness.  If we allow the
         * Door to be dropped without completely tearing everything down, it's
         * possible that our inner object will then be freed, invalidating the
         * pointer that we have used as a cookie for door_create(3C).
         */
        if let Err(e) = self.revoke() {
            /*
             * XXX upanic() here
             */
            panic!("door server still active on drop, revocation failed: {e}");
        }

        println!(
            "    DOOR DROP = refcount s {} w {}",
            Arc::strong_count(&self.inner),
            Arc::weak_count(&self.inner),
        );

        /*
         * Make sure we don't leak our inner object by leaving a reference in
         * the global registry:
         */
        //let reg = Registry::obtain();
        //reg.unregister(&self.inner);
    }
}

struct DoorClient {
    file: File,
    server_pid: libc::pid_t,
}

impl DoorClient {
    fn new<P: AsRef<Path>>(path: P) -> Result<DoorClient> {
        let path = path.as_ref();
        let file = File::open(path)
            .map_err(|e| anyhow!("opening door {path:?}: {e}"))?;

        let fd = file.as_raw_fd();

        let mut info: sys::DoorInfo = unsafe { std::mem::zeroed() };
        let r = unsafe { sys::door_info(fd, &mut info) };
        if r != 0 {
            let e = std::io::Error::last_os_error();
            bail!("could not get door info: {e}");
        }

        println!("info = {:#?}", info);
        Ok(DoorClient { file, server_pid: info.di_target })
    }

    fn dup_fd(fd: c_int) -> Result<DoorClient> {
        /*
         * Duplicate the file descriptor so that we can close it without
         * affecting the original.
         */
        let fd = unsafe {
            libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, libc::STDERR_FILENO + 1)
        };
        if fd < 0 {
            let e = std::io::Error::last_os_error();
            bail!("could not dup door fd: {e}");
        }

        let mut info: sys::DoorInfo = unsafe { std::mem::zeroed() };
        let r = unsafe { sys::door_info(fd, &mut info) };
        if r != 0 {
            unsafe { libc::close(fd) };
            let e = std::io::Error::last_os_error();
            bail!("could not get door info: {e}");
        }

        let file = unsafe { File::from_raw_fd(fd) };

        println!("client info = {:#?}", info);
        Ok(DoorClient { file, server_pid: info.di_target })
    }

    fn call(&self) -> Result<()> {
        let fd = self.file.as_raw_fd();

        let mut arg = sys::DoorArg {
            data_ptr: std::ptr::null_mut(),
            data_size: 0,
            desc_ptr: std::ptr::null_mut(),
            desc_num: 0,
            rbuf: std::ptr::null_mut(),
            rsize: 0,
        };

        let r = unsafe { sys::door_call(fd, &mut arg) };
        if r != 0 {
            let e = std::io::Error::last_os_error();

            match e.kind() {
                ErrorKind::Interrupted => bail!("door call interrupted"),
                _ => bail!("door call failure: {e}"),
            }
        }

        //println!("arg after call = {arg:#?}");

        Ok(())
    }
}

fn main() -> Result<()> {
    let door = "/tmp/THEDOOR";

    let opts = getopts::Options::new()
        .optflag("c", "", "be the client")
        .optflag("t", "", "be a LOT of clients")
        .parsing_style(getopts::ParsingStyle::StopAtFirstFree)
        .parse(std::env::args().skip(1))?;

    if opts.opt_present("t") {
        let dc = Arc::new(DoorClient::new(door)?);

        let threads: Vec<JoinHandle<String>> = (0..16)
            .map(|_| {
                let dc = Arc::clone(&dc);
                std::thread::spawn(move || loop {
                    match dc.call() {
                        Ok(_) => continue,
                        Err(e) => return format!("ERROR: {e}"),
                    }
                })
            })
            .collect::<Vec<_>>();

        for t in threads {
            t.join().unwrap();
        }

        return Ok(());
    }

    if opts.opt_present("c") {
        let dc = DoorClient::new(door)?;
        dc.call()?;
        return Ok(());
    }

    let d = Door::new(|a| {
        println!("door call! arg {a:?}");
        //panic!("oh no!");
    })?;

    let report = || {
        let wc = Arc::weak_count(&d.inner);
        let sc = Arc::strong_count(&d.inner);

        println!("--- {sc} refs, {wc} weak refs");
    };

    report();

    d.force_attach("/tmp/THEDOOR")?;

    report();

    println!("door server started; pid {}", std::process::id());

    //    /*
    //     * Can we call our own door server?
    //     */
    //    println!("---- own server:");
    //    let dc = DoorClient::dup_fd(d.door_fd())?;
    //    dc.call()?;
    //    dc.call()?;
    //    dc.call()?;
    //    dc.call()?;
    //    drop(dc);
    //    println!("---- own server^");

    println!("waiting for unref...");
    d.wait_for_unref();

    println!("closing threads...");
    d.revoke()?;

    Ok(())

    // println!("dropping...");
    // println!(
    //     "    = refcount s {} w {}",
    //     Arc::strong_count(&d.inner),
    //     Arc::weak_count(&d.inner),
    // );
    // drop(d);

    // println!("waiting...");
    // loop {
    //     std::thread::sleep(Duration::from_secs(1));
    // }
}
