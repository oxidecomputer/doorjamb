#![allow(unused_imports)]

use std::{
    any::Any,
    cell::{RefCell, UnsafeCell},
    ffi::CString,
    fs::File,
    io::ErrorKind,
    mem::MaybeUninit,
    os::{
        fd::{AsRawFd, BorrowedFd, FromRawFd, IntoRawFd, OwnedFd},
        unix::prelude::OsStrExt,
    },
    panic::RefUnwindSafe,
    path::Path,
    sync::{Arc, Condvar, Mutex, Weak},
    thread::JoinHandle,
    time::Duration,
};

use anyhow::{anyhow, bail, Result};
use client::DoorClient;
use libc::{c_char, c_uint, c_void, size_t};
use once_cell::sync::OnceCell;

pub mod client;

static ORIGINAL_CREATE_PROC: OnceCell<Option<sys::CreateProcFn>> =
    OnceCell::new();

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

#[allow(unused)]
mod sys;

fn upanic<S: AsRef<str>>(msg: S) -> ! {
    let msg = msg.as_ref();
    let b = msg.as_bytes();
    unsafe { sys::upanic(b.as_ptr() as *const c_char, b.len()) };
}

fn upanic_if_unwound<R>(
    msg: &'static str,
    res: std::result::Result<R, Box<dyn Any + Send>>,
) -> R {
    match res {
        Ok(res) => res,
        Err(payload) => {
            let storage;
            let msg = match payload.downcast_ref::<&'static str>() {
                Some(detail) => {
                    storage = format!("{msg}: {detail}");
                    &storage
                }
                None => match payload.downcast_ref::<String>() {
                    Some(detail) => {
                        storage = format!("{msg}: {detail}");
                        &storage
                    }
                    None => msg,
                },
            };

            upanic(msg);
        }
    }
}

#[allow(unused)]
struct Arg<'a> {
    arg: &'a [u8],
    descs: &'a [sys::DoorDesc],
    return_buffer: *mut [u8; RBUF_MAX],
}

impl<'a> Arg<'a> {
    fn as_bytes(&self) -> &[u8] {
        self.arg
    }

    fn make_return(&mut self) -> ReturnBuilder {
        /*
         * It's vital that we do not allow more than one mutable alias to the
         * underlying storage for the return buffer.
         */
        let buf =
            std::mem::replace(&mut self.return_buffer, std::ptr::null_mut());
        if buf.is_null() {
            panic!("cannot call make_return() twice");
        }

        ReturnBuilder { buf }
    }
}

pub struct ReturnBuilder {
    buf: *mut [u8; RBUF_MAX],
}

#[allow(unused)]
impl ReturnBuilder {
    fn buf(&mut self) -> &mut [u8; RBUF_MAX] {
        unsafe { &mut *self.buf }
    }

    fn u64(mut self, val: u64) -> Return {
        let buf = self.buf();

        let encoded = val.to_ne_bytes();
        buf[0..encoded.len()].copy_from_slice(&encoded);
        Return { len: encoded.len() }
    }

    fn i64(mut self, val: i64) -> Return {
        let buf = self.buf();

        let encoded = val.to_ne_bytes();
        buf[0..encoded.len()].copy_from_slice(&encoded);
        Return { len: encoded.len() }
    }

    fn u32(mut self, val: u32) -> Return {
        let buf = self.buf();

        let encoded = val.to_ne_bytes();
        buf[0..encoded.len()].copy_from_slice(&encoded);
        Return { len: encoded.len() }
    }

    fn i32(mut self, val: i32) -> Return {
        let buf = self.buf();

        let encoded = val.to_ne_bytes();
        buf[0..encoded.len()].copy_from_slice(&encoded);
        Return { len: encoded.len() }
    }

    fn string<S: AsRef<str>>(mut self, val: S) -> Return {
        let buf = self.buf();

        let val = val.as_ref();
        let encoded = val.as_bytes();
        assert!(encoded.len() < buf.len());
        buf[0..encoded.len()].copy_from_slice(encoded);
        buf[encoded.len()] = b'\0';
        Return { len: encoded.len() + 1 }
    }

    fn raw(mut self, func: impl FnOnce(&mut [u8]) -> usize) -> Return {
        let buf = self.buf();
        let len = func(buf);

        assert!(len <= buf.len());
        Return { len }
    }
}

#[derive(Debug)]
struct Return {
    len: usize,
}

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
    fd: Option<OwnedFd>,
    unref: bool,
    state: ServerState,
    threads: Vec<Arc<ServerThread>>,
}

struct DoorFuncBox<F> {
    func: F,
}

trait DoorFuncBoxCall: Sync + Send + RefUnwindSafe {
    fn call(&self, a: Arg) -> Return;
}

impl<F> DoorFuncBoxCall for DoorFuncBox<F>
where
    F: Sync + Send + Fn(Arg) -> Return + RefUnwindSafe,
{
    fn call(&self, a: Arg) -> Return {
        (self.func)(a)
    }
}

impl Drop for DoorInner {
    fn drop(&mut self) {
        let locked = self.locked.get_mut().unwrap();
        if let Some(fd) = locked.fd.as_ref() {
            panic!("door server: inner object dropped with open fd {fd:?}");
        }

        if !locked.threads.is_empty() {
            panic!(
                "door server: inner object dropped with threads: {:?}",
                locked.threads
            );
        }
    }
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
fn rust_door_thread_exit() {
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

/**
 * The maximum size of the return value buffer on the stack in the door server
 * procedure.
 */
const RBUF_MAX: usize = 64 * 1024;

#[no_mangle]
extern "C" fn rust_doors_server_proc(
    cookie: *mut c_void,
    argp: *mut c_char,
    arg_size: size_t,
    dp: *mut sys::DoorDesc,
    n_desc: c_uint,
) {
    /*
     * Allocate a large buffer on the stack for return values.  After processing
     * is complete, we must call door_return(3C) to submit results.  That call
     * does not return so there is no opportunity for drop handlers to run.  If
     * a larger return buffer is needed, we'll have to allocate from the heap
     * and stash it in the thread-local structure to free it the next time we're
     * woken up with a request.
     */
    let mut return_buffer: UnsafeCell<[u8; RBUF_MAX]> =
        UnsafeCell::new([0u8; RBUF_MAX]);

    let rbuf = return_buffer.get();

    let res = std::panic::catch_unwind(|| {
        /*
         * The door server object holds a reference to the inner object on
         * behalf of all threads.  The drop routine for that outer object will
         * not complete until all threads have been torn down, so it's safe to
         * use it here.
         */
        let di = cookie as *const DoorInner;

        /*
         * Because we created the door with DOOR_UNREF, if the door becomes
         * unreferenced we'll get a special invocation with the magic
         * DOOR_UNREF_DATA argument.  This can happen if the door path is
         * detached with an fdetach(3C) call or the fdetach program.  Note that
         * it does not strictly imply that there will be no further door calls.
         */
        let args = if argp == sys::DOOR_UNREF_DATA {
            None
        } else {
            Some((
                if argp.is_null() {
                    [].as_slice()
                } else {
                    unsafe {
                        std::slice::from_raw_parts(argp as *const u8, arg_size)
                    }
                },
                if dp.is_null() {
                    [].as_slice()
                } else {
                    unsafe {
                        std::slice::from_raw_parts(
                            dp as *const sys::DoorDesc,
                            n_desc.try_into().unwrap(),
                        )
                    }
                },
            ))
        };

        if let Some(ret) = rust_doors_server_proc_impl(di, args, rbuf) {
            Some(ret.len)
        } else {
            rust_door_thread_exit();
            None
        }
    });

    let Some(rbuflen) = upanic_if_unwound("executing door handler", res) else {
        return;
    };

    let rbufp = return_buffer.get_mut().as_mut_ptr();
    let r = unsafe {
        /*
         * NOTE: This call should not return.  This function must be careful not
         * to create anything that needs to be dropped to function correctly.
         */
        sys::door_return(rbufp as *mut i8, rbuflen, std::ptr::null_mut(), 0)
    };
    if r != -1 {
        upanic("door_return(3C) returned zero");
    }

    let e = unsafe { *libc::___errno() };
    if e == libc::EMFILE || e == libc::E2BIG {
        /*
         * These can occur if the return value was too large for the client to
         * handle, or the client was not prepared to receive as many file
         * descriptors as we sent.
         *
         * XXX If we start allowing the return of file descriptors, it seems
         * that it is our responsibility to clean them up in this instance.
         */
    }

    /*
     * XXX error channel?
     */
    eprintln!("DOOR RETURN FAILURE: e {e}");

    /*
     * If the client is not prepared to accept what we tried to return to them
     * there are no particularly good options left.  We can induce an EINTR
     * error in the client by exiting from this thread, which will at least not
     * be an empty reply that the client could misinterpret as meaningful.
     */
    let res = std::panic::catch_unwind(|| {
        rust_door_thread_exit();
    });

    upanic_if_unwound("exiting after failed door return", res);
}

#[no_mangle]
fn rust_doors_server_proc_impl(
    di: *const DoorInner,
    arg: Option<(&[u8], &[sys::DoorDesc])>,
    return_buffer: *mut [u8; RBUF_MAX],
) -> Option<Return> {
    /*
     * Fish our per-thread object out of thread local storage, without creating
     * a new reference.
     */
    let st: &ServerThread = {
        let st = DOOR_SERVER_THREAD.with(|st| *st.borrow());
        unsafe { &*st }
    };

    {
        let locked = st.locked.lock().unwrap();

        if locked.shutdown {
            /*
             * We're being torn down; don't look at anything else.
             */
            return None;
        }

        /*
         * Do some consistency checks between the per-thread object in our
         * thread local storage and the per-door object we've been passed as the
         * cookie.
         */
        if let Some(door) = locked.door.as_ref() {
            if door.as_ptr() != di {
                upanic(format!(
                    "inconsistent cookie: {:x} != {:x}",
                    door.as_ptr() as usize,
                    di as usize,
                ));
            }
        }
    }

    let di = unsafe { &*di };

    let Some((arg, descs)) = arg else {
        /*
         * If the door has become unreferenced, post that notification and exit
         * the thread.
         */
        di.locked.lock().unwrap().unref = true;
        di.cv.notify_all();
        return None;
    };

    /*
     * Call the door service routine provided by the user.
     */
    Some((di.func).call(Arg { arg, descs, return_buffer }))
}

impl Door {
    fn new<F>(func: F) -> Result<Door>
    where
        F: Fn(Arg) -> Return + Send + Sync + RefUnwindSafe + 'static,
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

        /*
         * We need to turn the inner object into a raw pointer that we can use
         * as a cookie value to pass to door_create(3C).  In the drop
         * implementation for Door, we'll abort the process if we cannot claw
         * the pointer back from the system before we drop our reference.
         */
        let cookie = Arc::as_ptr(&d.inner);

        /*
         * Create a door descriptor.
         */
        let fd = unsafe {
            sys::door_create(
                rust_doors_server_proc,
                cookie as *mut c_void,
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
            let _ = unsafe { Arc::from_raw(cookie) };
            bail!("could not create a door: {e}");
        }

        d.inner.locked.lock().unwrap().fd =
            Some(unsafe { OwnedFd::from_raw_fd(fd) });
        d.inner.cv.notify_all();

        Ok(d)
    }

    fn self_client(&self) -> Result<DoorClient> {
        let fd = if let Some(fd) = self.inner.locked.lock().unwrap().fd.as_ref()
        {
            fd.try_clone()?
        } else {
            bail!("could not create door client for this door");
        };

        fd.try_into()
    }

    fn attach_impl(&self, path: &Path, force: bool) -> Result<()> {
        let locked = self.inner.locked.lock().unwrap();

        let fd = match (&locked.state, &locked.fd) {
            (ServerState::Created, Some(fd)) => fd.as_raw_fd(),
            _ => bail!("cannot attach a door that is being revoked"),
        };

        let cpath = CString::new(path.as_os_str().as_bytes()).unwrap();

        if force {
            /*
             * First, remove an existing door if there is one.  A previous door
             * left attached by a terminated process will cause us to fail EBUSY
             * when we reattach.
             */
            unsafe { sys::fdetach(cpath.as_ptr()) };
            match std::fs::remove_file(path) {
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
            .open(path)
            .map_err(|e| anyhow!("creating {path:?}: {e}"))?;

        let r = unsafe { sys::fattach(fd, cpath.as_ptr()) };
        if r != 0 {
            let e = std::io::Error::last_os_error();
            bail!("unable to attach at {path:?}: {e}");
        }

        Ok(())
    }

    #[allow(unused)]
    fn attach<P: AsRef<Path>>(&self, path: P) -> Result<()> {
        self.attach_impl(path.as_ref(), false)
    }

    fn force_attach<P: AsRef<Path>>(&self, path: P) -> Result<()> {
        self.attach_impl(path.as_ref(), true)
    }

    fn wait_for_unref(&self) {
        let mut locked = self.inner.locked.lock().unwrap();
        while !locked.unref {
            locked = self.inner.cv.wait(locked).unwrap();
        }
    }

    fn revoke(&self) -> Result<()> {
        /*
         * We need to shut down each thread that is parked waiting to service a
         * door call.  This is perhaps surprisingly intricate: a thread parked
         * in door_return() waiting to service a call will unfortunately block
         * forever, even if it is bound to a particular private pool and the
         * door for that pool has been revoked.  Even though we have a list of
         * thread IDs for all of our private pool threads, we cannot use
         * thr_kill(3C) to kick them out because the door return logic always
         * restarts on EINTR without returning to code that we control.
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
         * exist because another process got to it first, we will block forever
         * -- or until the door is revoked.
         *
         * To avoid blocking this thread, we start _another_ thread whose sole
         * job is to make frenetic meaningless door calls until we have, here,
         * determined that there are no threads left to wake up.  At that time,
         * we'll revoke the door and then join our helper thread.  Note that to
         * avoid a race with our helper thread we must duplicate our original
         * file descriptor here; door_revoke(3C) will, as a side effect,
         * close(2) our original fd.
         *
         * First, mark the per-door object so that no more threads will be
         * created.
         */
        let (helper_fd, threads) = {
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

            let fd = if let Some(fd) = &locked.fd {
                fd.try_clone()?
            } else {
                /*
                 * XXX big if true
                 */
                bail!("no fd for door server");
            };

            locked.state = ServerState::Stopping;
            self.inner.cv.notify_all();

            /*
             * Inform all threads that we need to shut down.
             */
            for st in locked.threads.iter() {
                st.locked.lock().unwrap().shutdown = true;
                st.cv.notify_all();
            }

            (fd, std::mem::take(&mut locked.threads))
        };

        let jh = std::thread::spawn(move || loop {
            let mut arg = sys::DoorArg {
                data_ptr: std::ptr::null_mut(),
                data_size: 0,
                desc_ptr: std::ptr::null_mut(),
                desc_num: 0,
                rbuf: std::ptr::null_mut(),
                rsize: 0,
            };

            let r = unsafe { sys::door_call(helper_fd.as_raw_fd(), &mut arg) };
            let e = unsafe { *libc::___errno() };
            if r != 0 && e == libc::EBADF {
                /*
                 * door_call(3C) will fail with EBADF if the door has been
                 * revoked.  Unfortunately we cannot tell if this means we made
                 * a programming error with the file descriptor, and
                 * accidentally closed it before we meant to.
                 */
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

            if nactive == 0 {
                break;
            }

            std::thread::yield_now();
        }

        let fd = {
            let mut locked = self.inner.locked.lock().unwrap();
            let Some(fd) = locked.fd.take() else {
                /*
                 * XXX
                 */
                bail!("fd is gone?!");
            };

            /*
             * Make sure OwnedFd doesn't close the file descriptor; we'll do
             * that ourselves with door_revoke().
             */
            fd.into_raw_fd()
        };

        let r = unsafe { sys::door_revoke(fd) };
        let e = unsafe { *libc::___errno() };
        if r != 0 {
            /*
             * XXX probably leaking the fd here...
             */
            bail!("door_revoke failed -- r {r} e {e}");
        }

        jh.join().unwrap();

        let mut locked = self.inner.locked.lock().unwrap();
        assert!(locked.fd.is_none());
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
            upanic(format!(
                "door server still active on drop, revocation failed: {e}"
            ));
        }
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
            .map(|thr| {
                let dc = Arc::clone(&dc);
                std::thread::spawn(move || loop {
                    match dc.call() {
                        Ok(r) => println!("{thr}: res = {:?}", r.as_bytes()),
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
        let res = dc.call()?;
        println!("res = {:?}", res.as_bytes());
        return Ok(());
    }

    let d = Door::new(|mut a| {
        println!("door call! {:?}", a.as_bytes());

        //a.make_return().string("abcdef")

        a.make_return().raw(|buf| {
            buf[25] = b'A';
            26
        })

        //a.make_return().return_u64(0x0000000504030201)
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

    {
        /*
         * Can we call our own door server?
         */
        println!("---- own server:");

        let dc = d.self_client()?;
        for _ in 0..5 {
            let res = dc.call()?;

            println!("    result: {:?}", res.as_bytes());
        }
        drop(dc);

        println!("---- own server^");
    }

    println!("waiting for unref...");
    d.wait_for_unref();

    println!("closing threads...");
    d.revoke()?;

    Ok(())
}
