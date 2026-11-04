#![allow(dead_code)]
use std::path::PathBuf;
use veritas_fs::io::{FileSource, MemSource, Source};

pub const A_FILE: &[u8] = b"This is a text file.\n\nWe should be able to parse it.\n";

pub fn corpus(rel: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../testdata/corpus").join(rel)
}

pub fn src(rel: &str) -> Source {
    FileSource::source(&corpus(rel)).expect("corpus file present (testdata/fetch.py)")
}

pub fn bytes(rel: &str) -> Vec<u8> {
    std::fs::read(corpus(rel)).expect("corpus file present (testdata/fetch.py)")
}

pub fn mem(rel: &str) -> Source {
    MemSource::source(bytes(rel))
}
