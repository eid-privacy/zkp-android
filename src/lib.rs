#[macro_use]
mod stubs;

mod error;
pub use error::MoproError;

// Initializes the shared UniFFI scaffolding and defines the `MoproError` enum.
#[cfg(not(target_arch = "wasm32"))]
mopro_ffi::app!();
// Skip wasm_setup!() to avoid extern crate alias conflict
// Instead, we import wasm_bindgen directly when needed
#[cfg(all(feature = "wasm", target_arch = "wasm32"))]
use mopro_ffi::prelude::wasm_bindgen;

/// You can also customize the bindings by #[uniffi::export]
/// Reference: https://mozilla.github.io/uniffi-rs/latest/proc_macro/index.html
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn mopro_hello_world() -> String {
    "Hello, World!".to_string()
}

#[cfg_attr(
    all(feature = "wasm", target_arch = "wasm32"),
    wasm_bindgen(js_name = "moproWasmHelloWorld")
)]
pub fn mopro_wasm_hello_world() -> String {
    "Hello, World!".to_string()
}

#[cfg(test)]
mod uniffi_tests {
    #[test]
    fn test_mopro_hello_world() {
        assert_eq!(super::mopro_hello_world(), "Hello, World!");
    }
}


// CIRCOM_TEMPLATE
circom_stub!();

// HALO2_TEMPLATE
halo2_stub!();

// NOIR_TEMPLATE
// --- Noir Example of using Ultra Honk proving and verifying circuits ---

// Module containing the Noir circuit logic (Multiplier2)
mod noir;
pub use noir::{generate_noir_proof, get_noir_verification_key, verify_noir_proof,};

#[cfg(test)]
mod noir_tests {
    use super::noir::{generate_noir_proof, get_noir_verification_key, verify_noir_proof, get_holder_binding_abi, build_witness};
    use serial_test::serial;
    use serde_json::{Value, json};

    const HOLDER_BINDING_CIRCUIT_FILE: &str = "./test-vectors/noir/noir_c03_holder_binding.json";
    const HOLDER_BINDING_SRS_FILE: &str = "./test-vectors/noir/noir_c03_holder_binding.srs";
    const HOLDER_BINDING_VK_FILE: &str = "./test-vectors/noir/noir_c03_holder_binding.vk";

    const CREDENTIAL_STRING: &str = "Alice                           Smith                           09583416008caa0593dfd6510b118188f28e623eec9ffb719a4ecbc689a19d7de57b2a8182876001d8323c4a4cd8991c1cea15d4dbc12b463ac7b6d1e906c294c68f1766f70000000000134a37";
    const SIGNATURE_DEVICE: [u8; 64] = [171, 194, 24, 110, 235, 188, 255, 0, 116, 193, 34, 12, 208, 148, 158, 205, 151, 28, 248, 111, 202, 38, 199, 141, 79, 156, 109, 12, 29, 34, 145, 2, 94, 91, 197, 154, 1, 195, 92, 33, 10, 251, 17, 202, 101, 53, 119, 226, 18, 31, 60, 80, 244, 59, 167, 219, 61, 41, 116, 98, 34, 34, 134, 240];
    const CHALLENGE_HASH: [u8; 32] = [0, 138, 146, 177, 229, 156, 197, 31, 176, 9, 150, 122, 223, 240, 132, 57, 241, 241, 99, 238, 181, 138, 146, 139, 55, 61, 55, 61, 150, 81, 25, 39];

    #[test]
    #[serial]
    fn test_noir_holder_binding() {
        let low_memory_mode = false;
        let on_chain = true; // on_chain (uses Keccak for Solidity compatibility)
        let vk = get_noir_verification_key(
            HOLDER_BINDING_CIRCUIT_FILE.to_string().clone(),
            Some(HOLDER_BINDING_SRS_FILE.to_string().clone()),
            on_chain,
            low_memory_mode,
        )
        .unwrap();
        let input_json: serde_json::Value = json!({
            "credential_string": &CREDENTIAL_STRING,
            "signature_device": &SIGNATURE_DEVICE[..],
            "challenge_hash": &CHALLENGE_HASH[..],
        });
        let proof = generate_noir_proof(
            HOLDER_BINDING_CIRCUIT_FILE.to_string().clone(),
            Some(HOLDER_BINDING_SRS_FILE.to_string().clone()),
            &input_json.to_string(),
            on_chain,
            vk.clone(),
            low_memory_mode,
            "HolderBinding", // circuit type
        )
        .unwrap();

        let valid = verify_noir_proof(
            HOLDER_BINDING_CIRCUIT_FILE.to_string().clone(),
            proof,
            true, // on_chain (uses Keccak for Solidity compatibility)
            vk,
            false, // low_memory_mode
        )
        .unwrap();
        assert!(valid);
    }

// XXX does not pass
//    #[test]
//    #[serial]
//    fn test_noir_holder_binding_with_existing_vk() {
//        let low_memory_mode = false;
//        let on_chain = true; // on_chain (uses Keccak for Solidity compatibility)
//
//        // read vk from file as Vec<u8>
//        let vk = std::fs::read(HOLDER_BINDING_VK_FILE.to_string()).unwrap();
//
//        let input_json: serde_json::Value = json!({
//            "credential_string": &CREDENTIAL_STRING,
//            "signature_device": &SIGNATURE_DEVICE[..],
//            "challenge_hash": &CHALLENGE_HASH[..],
//        });
//
//        let proof = generate_noir_proof(
//            HOLDER_BINDING_CIRCUIT_FILE.to_string().clone(),
//            Some(HOLDER_BINDING_SRS_FILE.to_string().clone()),
//            &input_json.to_string(),
//            on_chain,
//            vk.clone(),
//            low_memory_mode,
//            "HolderBinding", // circuit type
//        )
//        .unwrap();
//
//        let valid = verify_noir_proof(
//            HOLDER_BINDING_CIRCUIT_FILE.to_string().clone(),
//            proof,
//            on_chain,
//            vk,
//            low_memory_mode,
//        )
//        .unwrap();
//        assert!(valid);
//    }
}

