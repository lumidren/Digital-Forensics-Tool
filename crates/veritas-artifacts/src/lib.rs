//! Artifact parsers. Every parser is safe Rust, bounds-checked, and returns `Err` rather than
//! panicking on malformed input. THREAT:T3.1
#![forbid(unsafe_code)]

pub mod error;
pub mod util;

// Registry hive and registry-derived artifacts (owner: registry module set).
pub mod regf;
pub mod registry;

// Binary artifact parsers (owner: binary module set).
pub mod evtx;
pub mod journald;
pub mod jumplist;
pub mod lnk;
pub mod olecf;
pub mod plist;
pub mod prefetch;
pub mod shellitems;
pub mod taskjob;

pub const PARSER_VERSION: &str = env!("CARGO_PKG_VERSION");
