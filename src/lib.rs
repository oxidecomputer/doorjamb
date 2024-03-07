/*
 * Copyright 2024 Oxide Computer Company
 */

/*
 * This crate contains many routines that are passed as callbacks to C code, and
 * which then dereference raw pointers.  We want to mark any such function as
 * unsafe, but we don't want that to imply the entire function body is then
 * unsafe.
 */
#![deny(unsafe_op_in_unsafe_fn)]

pub mod args;
pub mod client;
pub mod server;
#[allow(unused)]
mod sys;
mod threads;
mod upanic;

pub mod prelude {
    pub use crate::client::DoorClient;
    pub use crate::server::DoorServer;
}
