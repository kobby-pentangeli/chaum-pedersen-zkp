#![no_main]

use chaum_pedersen::{Group, Ristretto255, Statement};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.len() < 64 {
        return;
    }

    let y1_bytes = &data[..32];
    let y2_bytes = &data[32..64];

    if let Ok(y1) = Ristretto255::element_from_bytes(y1_bytes) {
        if let Ok(y2) = Ristretto255::element_from_bytes(y2_bytes) {
            let statement = Statement::new(y1, y2);
            let _ = statement.validate();
        }
    }
});
