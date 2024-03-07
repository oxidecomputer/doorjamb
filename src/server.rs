/*
 * Copyright 2024 Oxide Computer Company
 */

use std::{
    cell::UnsafeCell,
    ffi::CString,
    io::ErrorKind,
    os::{
        fd::{AsRawFd, FromRawFd, IntoRawFd, OwnedFd},
        unix::prelude::OsStrExt,
    },
    panic::RefUnwindSafe,
    path::Path,
    sync::{Arc, Condvar, Mutex},
};

use crate::args::*;
use crate::client::DoorClient;
use crate::sys;
use crate::threads;
use crate::upanic::*;
use anyhow::{anyhow, bail, Result};
use libc::{c_char, c_uint, c_void, size_t};

pub struct DoorServer {
    inner: Arc<DoorInner>,
}

pub(crate) enum ServerState {
    Created,
    Stopping,
    Stopped,
}

pub(crate) struct DoorInner {
    pub(crate) func: Box<dyn DoorFuncBoxCall>,

    pub(crate) cv: Condvar,
    pub(crate) locked: Mutex<DoorLocked>,
}

pub(crate) struct DoorLocked {
    pub(crate) fd: Option<OwnedFd>,
    pub(crate) unref: bool,
    pub(crate) state: ServerState,
    pub(crate) threads: Vec<Arc<threads::ServerThread>>,
}

pub(crate) struct DoorFuncBox<F> {
    func: F,
}

pub(crate) trait DoorFuncBoxCall: Sync + Send + RefUnwindSafe {
    fn call(&self, a: DoorArg) -> DoorReturn;
}

impl<F> DoorFuncBoxCall for DoorFuncBox<F>
where
    F: Sync + Send + Fn(DoorArg) -> DoorReturn + RefUnwindSafe,
{
    fn call(&self, a: DoorArg) -> DoorReturn {
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

/**
 * The maximum size of the return value buffer on the stack in the door server
 * procedure.  According to thr_create(3C), 64-bit processes have 2MiB stacks by
 * default, so 64KiB seems not unreasonable as a starting position.
 */
pub(crate) const RBUF_MAX: usize = 64 * 1024;

#[no_mangle]
pub(crate) unsafe extern "C" fn rust_doors_server_proc(
    cookie: *mut c_void,
    argp: *mut c_char,
    arg_size: size_t,
    dp: *mut sys::DoorDesc,
    n_desc: c_uint,
) {
    /*
     * Allocate a large buffer on the stack for return values.  After processing
     * is complete, we must call door_return(3C) to submit results.  That call
     * does not return so there is no opportunity for drop handlers to run.
     *
     * If a larger return buffer is needed in the future, we'll have to allocate
     * from the heap and stash it in the thread-local structure to free it the
     * next time we're woken up with a request.
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

        let args = if argp == sys::DOOR_UNREF_DATA {
            /*
             * Because we created the door with DOOR_UNREF, if the door becomes
             * unreferenced we'll get a special invocation with the magic
             * DOOR_UNREF_DATA argument.  This can happen if the door path is
             * detached with an fdetach(3C) call or the fdetach program.  Note
             * that it does not strictly imply that there will be no further
             * door calls.
             */
            None
        } else {
            /*
             * Otherwise, try to turn the argument pointers into slices.  We are
             * careful to check both the pointers and the length here.  A null
             * pointer would obviously mean no values were passed, but it is
             * conceivable that other sentinel values like DOOR_UNREF_DATA could
             * be passed in future with a zero length as well.
             */
            Some((
                if argp.is_null() || arg_size == 0 {
                    [].as_slice()
                } else {
                    unsafe {
                        std::slice::from_raw_parts(argp as *const u8, arg_size)
                    }
                },
                if dp.is_null() || n_desc == 0 {
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

        if let Some(ret) =
            unsafe { rust_doors_server_proc_impl(di, args, rbuf) }
        {
            Some(ret.len)
        } else {
            threads::rust_door_thread_exit();
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
        threads::rust_door_thread_exit();
    });

    upanic_if_unwound("exiting after failed door return", res);
}

#[no_mangle]
unsafe fn rust_doors_server_proc_impl(
    di: *const DoorInner,
    arg: Option<(&[u8], &[sys::DoorDesc])>,
    return_buffer: *mut [u8; RBUF_MAX],
) -> Option<DoorReturn> {
    /*
     * Fish our per-thread object out of thread local storage, without creating
     * a new reference.
     */
    let st = threads::borrow_thread_local();

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
    Some((di.func).call(DoorArg { arg, descs, return_buffer }))
}

impl DoorServer {
    pub fn new<F>(func: F) -> Result<DoorServer>
    where
        F: Fn(DoorArg) -> DoorReturn + Send + Sync + RefUnwindSafe + 'static,
    {
        threads::install_create_proc();

        /*
         * First, create our tracking object.  We need to do this prior to door
         * creation so that we can use its memory address as the cookie address
         * to pass to the door.
         */
        let d = DoorServer {
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
         * implementation for DoorServer, we'll abort the process if we cannot
         * claw the pointer back from the system before we drop our reference.
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

    pub fn self_client(&self) -> Result<DoorClient> {
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

    pub fn attach<P: AsRef<Path>>(&self, path: P) -> Result<()> {
        self.attach_impl(path.as_ref(), false)
    }

    pub fn force_attach<P: AsRef<Path>>(&self, path: P) -> Result<()> {
        self.attach_impl(path.as_ref(), true)
    }

    pub fn wait_for_unref(&self) {
        let mut locked = self.inner.locked.lock().unwrap();
        while !locked.unref {
            locked = self.inner.cv.wait(locked).unwrap();
        }
    }

    pub fn revoke(&self) -> Result<()> {
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
                 * a programming error with the file descriptor and accidentally
                 * closed it before we meant to.
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
                        threads::ServerThreadState::Exited,
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

impl Drop for DoorServer {
    fn drop(&mut self) {
        /*
         * NOTE: This revoke call is vital for correctness.  If we allow the
         * DoorServer to be dropped without completely tearing everything down,
         * it's possible that our inner object will then be freed, invalidating
         * the pointer that we have used as a cookie for door_create(3C).
         */
        if let Err(e) = self.revoke() {
            upanic(format!(
                "door server still active on drop, revocation failed: {e}"
            ));
        }
    }
}
