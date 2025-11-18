#![no_main]

use chaum_pedersen::{Proof, Ristretto255};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = Proof::from_bytes::<Ristretto255>(data);
});
