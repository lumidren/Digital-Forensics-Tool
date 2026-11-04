//! Fuzz shell item ID list parsing (shared by LNK and ShellBags).
#![no_main]
use libfuzzer_sys::fuzz_target;
use veritas_artifacts::shellitems;

fuzz_target!(|data: &[u8]| {
    if let Ok(items) = shellitems::parse_shell_item_list(data) {
        let _ = shellitems::shell_item_path(&items);
    }
});
