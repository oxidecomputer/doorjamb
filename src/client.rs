/*
 * Copyright 2024 Oxide Computer Company
 */

use std::{
    fs::File,
    io::ErrorKind,
    mem::MaybeUninit,
    os::fd::{AsRawFd, OwnedFd},
    path::Path,
};

use crate::sys;
use anyhow::{anyhow, bail, Result};
use libc::{c_char, c_void};

pub struct DoorClient {
    fd: OwnedFd,
    server_pid: libc::pid_t,
}

impl TryFrom<OwnedFd> for DoorClient {
    type Error = anyhow::Error;

    fn try_from(fd: OwnedFd) -> Result<Self> {
        let mut info: sys::DoorInfo = unsafe { std::mem::zeroed() };

        let r = unsafe { sys::door_info(fd.as_raw_fd(), &mut info) };
        if r != 0 {
            let e = std::io::Error::last_os_error();
            bail!("could not get door info: {e}");
        }

        Ok(DoorClient { fd, server_pid: info.di_target })
    }
}

impl DoorClient {
    pub fn new<P: AsRef<Path>>(path: P) -> Result<DoorClient> {
        let path = path.as_ref();
        let file = File::open(path)
            .map_err(|e| anyhow!("opening door {path:?}: {e}"))?;

        let fd: OwnedFd = file.into();

        fd.try_into()
    }

    pub fn call(&self) -> Result<DoorResult> {
        self.call_with_buf(&[])
    }

    pub fn call_with_buf(&self, data: &[u8]) -> Result<DoorResult> {
        let fd = self.fd.as_raw_fd();
        let mut dr = DoorResult::new();

        if !data.is_empty() {
            dr.arg.data_ptr = data.as_ptr() as *mut i8;
            dr.arg.data_size = data.len();
        }

        let r = unsafe { sys::door_call(fd, &mut dr.arg) };
        if r != 0 {
            let e = std::io::Error::last_os_error();

            match e.kind() {
                ErrorKind::Interrupted => bail!("door call interrupted"),
                _ => bail!("door call failure: {e}"),
            }
        }

        Ok(dr)
    }

    pub fn server_pid(&self) -> u32 {
        self.server_pid.try_into().unwrap()
    }

    pub fn into_owned_fd(self) -> OwnedFd {
        self.fd
    }
}

const INCLUDED_BUFFER_LEN: usize = 4096;

#[derive(Debug)]
pub struct DoorResult {
    buf: Box<MaybeUninit<[u8; INCLUDED_BUFFER_LEN]>>,
    arg: sys::DoorArg,
}

impl DoorResult {
    fn new() -> DoorResult {
        /*
         * We want a region of memory with an address that doesn't move around.
         */
        let mut buf = Box::new(MaybeUninit::uninit());

        DoorResult {
            arg: sys::DoorArg {
                data_ptr: std::ptr::null_mut(),
                data_size: 0,
                desc_ptr: std::ptr::null_mut(),
                desc_num: 0,
                rbuf: buf.as_mut_ptr() as *mut c_char,
                rsize: INCLUDED_BUFFER_LEN,
            },
            buf,
        }
    }

    pub fn as_bytes(&self) -> &[u8] {
        if self.arg.data_ptr.is_null() || self.arg.data_size == 0 {
            &[]
        } else {
            unsafe {
                std::slice::from_raw_parts(
                    self.arg.data_ptr as *const u8,
                    self.arg.data_size,
                )
            }
        }
    }

    pub fn descriptors(&self) -> &[sys::DoorDesc] {
        if self.arg.desc_ptr.is_null() || self.arg.desc_num == 0 {
            &[]
        } else {
            unsafe {
                std::slice::from_raw_parts(
                    self.arg.desc_ptr,
                    self.arg.desc_num.try_into().unwrap(),
                )
            }
        }
    }
}

impl Drop for DoorResult {
    fn drop(&mut self) {
        if self.arg.rbuf != (self.buf.as_mut_ptr() as *mut c_char) {
            let r = unsafe {
                libc::munmap(self.arg.rbuf as *mut c_void, self.arg.rsize)
            };
            if r != 0 {
                let e = std::io::Error::last_os_error();
                panic!(
                    "munmap door result (0x{:x} len 0x{:x}): {e}",
                    self.arg.rbuf as usize, self.arg.rsize
                );
            }
        }
    }
}
