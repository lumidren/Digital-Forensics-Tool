//! veritas-fs: volume and file-system parsers for disk images.
//!
//! Every parser is safe Rust, bounds-checks each offset and length, caps recursion depth and loop
//! iterations (limits are documented `pub const`s in each module) and returns `Err` rather than
//! panicking on malformed input. THREAT:T3.1 THREAT:T3.2
//! Output is deterministic: `BTreeMap`s and sorted vectors only, no wall-clock reads.
#![forbid(unsafe_code)]

pub mod error;
pub mod io;
pub mod util;

pub mod volume;
pub mod ntfs;
pub mod fat;
pub mod ext4;
pub mod apfs;
pub mod vss;

pub mod carve;
pub mod events;
pub mod harvest;
pub mod image;
pub mod recover;

pub use error::{FsError, Result};

pub const PARSER_VERSION: &str = env!("CARGO_PKG_VERSION");
