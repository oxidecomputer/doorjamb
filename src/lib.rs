/*
 * Copyright 2024 Oxide Computer Company
 */

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
