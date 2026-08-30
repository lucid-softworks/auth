//! Native authentication with Better Auth-compatible host and D1 surfaces.

#![cfg_attr(target_arch = "wasm32", allow(dead_code))]

#[cfg(target_arch = "wasm32")]
include!("wasm.rs");
#[cfg(not(target_arch = "wasm32"))]
include!("host.rs");
