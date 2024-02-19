use libc::{c_char, c_int, c_uint, c_void, size_t};
use once_cell::sync::OnceCell;
use std::{
    cell::RefCell,
    path::Path,
    sync::{Arc, Mutex},
};

use anyhow::{bail, Result};

static REGISTRY: OnceCell<Registry> = OnceCell::new();
static ORIGINAL_CREATE_PROC: OnceCell<sys::CreateProcFn> = OnceCell::new();

#[derive(Default)]
struct Registry {
    cookies: Mutex<Vec<Arc<DoorInner>>>,
}

impl Registry {
    /**
     * Obtain a reference to the global registry for all door servers created by
     * this library.
     */
    fn obtain() -> &'static Registry {
        /*
         * Install our door thread creation procedure, stashing the original one
         * so that we can chain calls to it for doors that do not belong to us.
         */
        ORIGINAL_CREATE_PROC.get_or_init(|| unsafe {
            sys::door_server_create(rust_door_create_proc)
        });

        REGISTRY.get_or_init(|| Registry::default())
    }

    fn register(&self, di: &Arc<DoorInner>) {
        let mut cookies = self.cookies.lock().unwrap();

        /*
         * Make sure this door object is not already registered.
         */
        for c in cookies.iter() {
            if Arc::as_ptr(c) == Arc::as_ptr(di) {
                panic!("double registration?");
            }
        }

        /*
         * Take a hold on the inner door object that we use for the cookie
         * pointer.  This will prevent it from being freed until we revoke it.
         */
        cookies.push(Arc::clone(&di));
    }

    fn locate(&self, cookie: *mut c_void) -> Option<Arc<DoorInner>> {
        let cookies = self.cookies.lock().unwrap();

        for c in cookies.iter() {
            if Arc::as_ptr(c) == (cookie as *const DoorInner) {
                let di = Arc::clone(&c);
                assert_eq!(Arc::as_ptr(&di) as *mut c_void, cookie);
                return Some(Arc::clone(&c));
            }
        }

        None
    }
}

#[allow(unused)]
mod sys;

struct Arg {}

struct Door {
    inner: Arc<DoorInner>,
}

struct DoorInner {
    func: Box<dyn Fn(Arg) + Send + Sync>,
    fd: OnceCell<c_int>,
}

impl Drop for DoorInner {
    fn drop(&mut self) {
        println!("door fd {:?} dropped", self.fd.get());
    }
}

extern "C" fn rust_door_create_proc(infop: *mut sys::DoorInfo) {
    /*
     * Make sure this door is one created with DOOR_PRIVATE:
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

    /*
     * Confirm that the door server procedure is our wrapper:
     */
    if (info.di_attributes & sys::DOOR_PRIVATE) == 0
        || info.di_proc != (rust_doors_server_proc as *mut c_void)
    {
        if let Some(create_proc) = ORIGINAL_CREATE_PROC.get() {
            create_proc(infop);
        }
        return;
    }

    /*
     * Look up the cookie in the registry.
     */
    let reg = Registry::obtain();
    let Some(di) = reg.locate(info.di_data) else {
        return;
    };

    /*
     * Create a thread and pass the door data to it.
     */
    let arg = Arc::into_raw(di);

    let r = unsafe {
        sys::thr_create(
            std::ptr::null_mut(),
            0,
            rust_door_thread,
            arg as *mut c_void,
            sys::THR_DETACHED,
            std::ptr::null_mut(),
        )
    };

    if r == 0 {
        /*
         * Thread creation was successful.  Yield to allow it to begin running,
         * like the default implementation in libc does.
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

extern "C" fn rust_door_thread(arg: *mut c_void) -> *mut c_void {
    /*
     * Turn the raw pointer back into an Arc so that we'll drop it when we leave
     * this function, but not before.  This should keep the allocation alive
     * while we service door calls, which essentially happens during the
     * door_return() call below.
     */
    let di: Arc<DoorInner> = unsafe { Arc::from_raw(arg as *const DoorInner) };

    /*
     * It should be safe to unwrap this.  We do not expect any door calls until
     * after we've put the fd in place here.
     */
    let fd = *di.fd.get().unwrap();

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
        return std::ptr::null_mut();
    }

    /*
     * Calling door_return(3C) with all zero values informs the OS that this
     * thread is ready to service door calls.
     */
    unsafe {
        sys::door_return(std::ptr::null_mut(), 0, std::ptr::null_mut(), 0)
    };

    /*
     * We don't want to be considered for the private thread pool for this door
     * anymore.
     */
    unsafe { sys::door_unbind() };

    /*
     * We are a detached thread so our return value is meaningless:
     */
    std::ptr::null_mut()
}

extern "C" fn rust_doors_server_proc(
    cookie: *mut c_void,
    argp: *mut c_char,
    arg_size: size_t,
    dp: *mut sys::door_desc_t,
    n_desc: c_uint,
) {
    /*
     * When creating the door server thread, we took a reference on the door
     * object.  It's safe to just dereference it here, as it won't be freed
     * until after we've been back through door_return() and control has
     * returned to door_thread().
     */
    let di = cookie as *const DoorInner;

    if argp == sys::DOOR_UNREF_DATA {
        println!("DOOR HAS BECOME UNREF!");
        return;
    }

    println!("calling door func()...");
    unsafe { &*di }.func.as_ref()(Arg {});
    println!("back from door func()");

    let r = unsafe {
        /*
         * NOTE: This call should not return.  This function must be careful not
         * to create anything that needs to be dropped to function correctly.
         */
        sys::door_return(std::ptr::null_mut(), 0, std::ptr::null_mut(), 0)
    };
    if r == -1 {
        let e = std::io::Error::last_os_error();
        panic!("door_return() failure: {e}");
    }
    unreachable!();
}

impl Door {
    fn new(path: &Path, func: Box<dyn Fn(Arg) + Send + Sync>) -> Result<Door> {
        /*
         * First, create a unique cookie pointer for this door.
         */
        let reg = Registry::obtain();

        /*
         * First, create our tracking object.  We need to do this prior to door
         * creation so that we can use its memory address as the cookie address
         * to pass to the door.
         */
        let d = Door {
            inner: Arc::new(DoorInner { func, fd: Default::default() }),
        };

        /*
         * Create a new Arc reference and turn it into a raw pointer.  We'll use
         * this as the cookie value so that our server procedure can
         * reconstitute the Door object.
         */
        let cookie = Arc::into_raw(Arc::clone(&d.inner));

        /*
         * Create a door descriptor.
         */
        let fd = unsafe {
            sys::door_create(
                rust_doors_server_proc,
                cookie as *mut DoorInner as *mut c_void,
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
            /*
             * Get our raw reference back so that we can drop it:
             */
            let _ = unsafe { Arc::from_raw(cookie) };
            bail!("could not create a door: {e}");
        }

        d.inner.fd.set(fd).unwrap();

        /*
         * XXX fattach() now...
         */

        Ok(d)
    }
}

fn main() -> Result<()> {
    Ok(())
}

// #[cfg(test)]
// mod test {
//     use std::sync::{Arc, Weak};
// 
//     #[test]
//     fn arcs() {
//         struct Trial {
//             s: String,
//             a: u64,
//         }
// 
//         let at = Arc::new(Trial { s: "blah blah!".into(), a: 12345 });
// 
//         let report = || {
//             println!(
//                 "weak count = {}, strong count = {}",
//                 Arc::weak_count(&at),
//                 Arc::strong_count(&at)
//             );
//         };
// 
//         println!();
//         report();
// 
//         let at1 = Arc::into_raw(Arc::clone(&at));
//         report();
// 
//         let at2 = Arc::into_raw(Arc::clone(&at));
//         report();
// 
//         println!("at ptr = {:x}", Arc::as_ptr(&at) as usize);
//         println!("at1 = {:x}", at1 as usize);
//         println!("at2 = {:x}", at2 as usize);
// 
//         unsafe { Arc::increment_strong_count(at1) };
//         report();
// 
//         unsafe { Arc::increment_strong_count(at2) };
//         report();
// 
//         let at2s = unsafe { Arc::from_raw(at2) };
//         report();
// 
//         let w1 = Arc::downgrade(&at);
//         report();
// 
//         let w1r = Weak::into_raw(w1);
//         println!("w1r = {:x}", w1r as usize);
// 
//         let w2 = Arc::downgrade(&at);
//         report();
// 
//         let w2r = Weak::into_raw(w2);
//         println!("w2r = {:x}", w2r as usize);
// 
//         drop(at2s);
//         report();
//     }
// }
