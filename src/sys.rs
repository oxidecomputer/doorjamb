/*
 * Copyright 2024 Oxide Computer Company
 */

use libc::{c_char, c_int, c_long, c_uint, c_ulonglong, c_void, pid_t, size_t};

pub type ServerProcedureFn = unsafe extern "C" fn(
    *mut c_void,
    *mut c_char,
    size_t,
    *mut DoorDesc,
    c_uint,
);

pub type CreateProcFn = unsafe extern "C" fn(*mut DoorInfo);

#[derive(Debug)]
#[repr(C, packed(4))]
pub struct DoorInfo {
    pub di_target: pid_t,
    pub di_proc: *const c_void,
    pub di_data: *mut c_void,
    pub di_attributes: c_uint,
    pub di_uniquifier: c_ulonglong,
    pub di_resv: [c_int; 4],
}

#[repr(C, packed(4))]
pub struct DoorDesc {
    pub d_attributes: c_uint,
    pub d_data: DoorDescData,
}

impl std::fmt::Debug for DoorDesc {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        /*
         * XXX
         */
        write!(f, "<DoorDesc>")
    }
}

#[repr(C)]
pub union DoorDescData {
    pub d_desc: DoorDescDataFd,
    pub d_resv: c_int,
}

#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct DoorDescDataFd {
    pub d_descriptor: c_int,
    pub d_id: c_ulonglong,
}

#[derive(Debug)]
#[repr(C)]
pub struct DoorArg {
    pub data_ptr: *mut c_char,
    pub data_size: size_t,
    pub desc_ptr: *mut DoorDesc,
    pub desc_num: c_uint,
    pub rbuf: *mut c_char,
    pub rsize: size_t,
}

extern "C" {
    pub fn door_create(
        server_procedure: ServerProcedureFn,
        cookie: *mut c_void,
        attributes: c_uint,
    ) -> c_int;

    pub fn door_revoke(d: c_int) -> c_int;

    /**
     * Associates the current thread with a door server pool.  Doors created
     * with DOOR_PRIVATE will only use threads explicitly bound with this
     * function.
     */
    pub fn door_bind(did: c_int) -> c_int;

    /**
     * Breaks the association of the current thread with a door server pool.
     */
    pub fn door_unbind() -> c_int;

    pub fn fattach(fildes: c_int, path: *const c_char) -> c_int;
    pub fn fdetach(path: *const c_char) -> c_int;

    pub fn door_return(
        data_ptr: *mut c_char,
        data_size: size_t,
        desc_ptr: *mut DoorDesc,
        num_desc: c_uint,
    ) -> c_int;

    pub fn door_call(d: c_int, params: *mut DoorArg) -> c_int;

    pub fn door_server_create(
        create_proc: CreateProcFn,
    ) -> Option<CreateProcFn>;

    pub fn door_info(d: c_int, info: *mut DoorInfo) -> c_int;

    pub fn pthread_setcancelstate(state: c_int, oldstate: *mut c_int) -> c_int;

    pub fn thr_create(
        stack_base: *mut c_void,
        stack_size: size_t,
        start_func: unsafe extern "C" fn(*mut c_void) -> *mut c_void,
        arg: *mut c_void,
        flags: c_long,
        new_thread_id: *mut c_uint,
    ) -> c_int;

    pub fn thr_setname(tid: c_uint, name: *const c_char) -> c_int;

    pub fn thr_self() -> c_uint;

    pub fn upanic(msg: *const c_char, len: size_t) -> !;
}

pub const PTHREAD_CANCEL_DISABLE: c_int = 0x01;

pub const THR_DETACHED: c_long = 0x40;

/**
 * Deliver an unref notification with door.
 */
pub const DOOR_UNREF: c_uint = 0x01;
/**
 * Use a private pool of server threads.
 */
pub const DOOR_PRIVATE: c_uint = 0x02;
/**
 * Deliver unref notification more than once.
 */
pub const DOOR_UNREF_MULTI: c_uint = 0x10;
/**
 * Do not accept descriptors from callers.
 */
pub const DOOR_REFUSE_DESC: c_uint = 0x40;
/**
 * No server thread cancel on client abort.
 */
pub const DOOR_NO_CANCEL: c_uint = 0x80;

/**
 * Special sentinel data argument passed to server procedure for unreferenced
 * events.
 */
pub const DOOR_UNREF_DATA: *mut c_char = 1 as *mut c_char;
