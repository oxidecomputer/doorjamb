/*
 * Copyright 2024 Oxide Computer Company
 */

use crate::server::RBUF_MAX;
use crate::sys;

#[allow(unused)]
pub struct DoorArg<'a> {
    pub(crate) arg: &'a [u8],
    pub(crate) descs: &'a [sys::DoorDesc],
    pub(crate) return_buffer: *mut [u8; RBUF_MAX],
}

impl<'a> DoorArg<'a> {
    pub fn as_bytes(&self) -> &[u8] {
        self.arg
    }

    pub fn make_return(&mut self) -> ReturnBuilder {
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
    pub fn buf(&mut self) -> &mut [u8; RBUF_MAX] {
        unsafe { &mut *self.buf }
    }

    pub fn u64(mut self, val: u64) -> DoorReturn {
        let buf = self.buf();

        let encoded = val.to_ne_bytes();
        buf[0..encoded.len()].copy_from_slice(&encoded);
        DoorReturn { len: encoded.len() }
    }

    pub fn i64(mut self, val: i64) -> DoorReturn {
        let buf = self.buf();

        let encoded = val.to_ne_bytes();
        buf[0..encoded.len()].copy_from_slice(&encoded);
        DoorReturn { len: encoded.len() }
    }

    pub fn u32(mut self, val: u32) -> DoorReturn {
        let buf = self.buf();

        let encoded = val.to_ne_bytes();
        buf[0..encoded.len()].copy_from_slice(&encoded);
        DoorReturn { len: encoded.len() }
    }

    pub fn i32(mut self, val: i32) -> DoorReturn {
        let buf = self.buf();

        let encoded = val.to_ne_bytes();
        buf[0..encoded.len()].copy_from_slice(&encoded);
        DoorReturn { len: encoded.len() }
    }

    pub fn string<S: AsRef<str>>(mut self, val: S) -> DoorReturn {
        let buf = self.buf();

        let val = val.as_ref();
        let encoded = val.as_bytes();
        assert!(encoded.len() < buf.len());
        buf[0..encoded.len()].copy_from_slice(encoded);
        buf[encoded.len()] = b'\0';
        DoorReturn { len: encoded.len() + 1 }
    }

    pub fn raw(mut self, func: impl FnOnce(&mut [u8]) -> usize) -> DoorReturn {
        let buf = self.buf();
        let len = func(buf);

        assert!(len <= buf.len());
        DoorReturn { len }
    }
}

#[derive(Debug)]
pub struct DoorReturn {
    pub(crate) len: usize,
}
