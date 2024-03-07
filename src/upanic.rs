/*
 * Copyright 2024 Oxide Computer Company
 */

use std::any::Any;

use crate::sys;
use libc::c_char;

pub fn upanic<S: AsRef<str>>(msg: S) -> ! {
    let msg = msg.as_ref();
    let b = msg.as_bytes();
    unsafe { sys::upanic(b.as_ptr() as *const c_char, b.len()) };
}

pub fn upanic_if_unwound<R>(
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
