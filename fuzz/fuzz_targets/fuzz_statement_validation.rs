#![no_main]

use chaum_pedersen::{Element, Statement};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.len() < 64 {
        return;
    }

    if let (Ok(y1), Ok(y2)) = (
        Element::from_bytes(&data[..32]),
        Element::from_bytes(&data[32..64]),
    ) {
        let _ = Statement::new(y1, y2);
    }
});
