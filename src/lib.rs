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

    // circuit and SRS paths
    macro_rules! TEST_VECTORS {
        () => {
            "./test-vectors/noir/"
        };
    }
    const HOLDER_BINDING_CIRCUIT_FILE: &str = concat!(TEST_VECTORS!(), "noir_c03_holder_binding.json");
    const HOLDER_BINDING_SRS_FILE: &str = concat!(TEST_VECTORS!(), "noir_c03_holder_binding.srs");
    const ISSUER_SIGNATURE_CIRCUIT_FILE: &str = concat!(TEST_VECTORS!(), "noir_c04_issuer_signature.json");
    const ISSUER_SIGNATURE_SRS_FILE: &str = concat!(TEST_VECTORS!(), "noir_c04_issuer_signature.srs");
    const AGE_VERIFICATION_CIRCUIT_FILE: &str = concat!(TEST_VECTORS!(), "noir_c05_age_verification.json");
    const AGE_VERIFICATION_SRS_FILE: &str = concat!(TEST_VECTORS!(), "noir_c05_age_verification.srs");
    const NON_REVOCATION_CIRCUIT_FILE: &str = concat!(TEST_VECTORS!(), "noir_c06_non_revocation.json");
    const NON_REVOCATION_SRS_FILE: &str = concat!(TEST_VECTORS!(), "noir_c06_non_revocation.srs");
    const FULL_PROOF_CIRCUIT_FILE: &str = concat!(TEST_VECTORS!(), "noir_c09_full_proof.json");
    const FULL_PROOF_SRS_FILE: &str = concat!(TEST_VECTORS!(), "noir_c09_full_proof.srs");

    // input
    // Prover_0
    const CURRENT_DATE: u64 = 1762449600;
    const PUBKEY_ISSUER_X: [u8; 32] = [126, 248, 106, 31, 85, 42, 214, 184, 182, 133, 99, 87, 93, 36, 227, 150, 248, 59, 139, 226, 147, 161, 12, 54, 239, 26, 245, 148, 118, 133, 77, 8];
    const PUBKEY_ISSUER_Y: [u8; 32] = [209, 78, 91, 83, 6, 68, 60, 60, 249, 26, 250, 42, 66, 55, 166, 202, 77, 147, 71, 8, 246, 169, 110, 76, 139, 254, 162, 163, 96, 251, 115, 69];
    const CREDENTIAL_STRING: &str = "Alice                           Smith                           095834160096ae308132a110a2fdc6cd3b68658102d43a45cdd6d758586b4ad63b92dc221d4f08d8067c51d7b1a4a814e5eff0e389fb7f23110965f406286cd8e5eadac03e0000000000134a37";
    const SIGNATURE_ISSUER: [u8; 64] = [238, 166, 185, 25, 45, 42, 145, 240, 143, 160, 111, 109, 229, 64, 72, 151, 236, 118, 97, 17, 42, 125, 19, 240, 163, 114, 20, 56, 139, 58, 86, 17, 88, 102, 202, 59, 253, 200, 232, 45, 44, 234, 48, 76, 157, 88, 242, 122, 60, 19, 132, 177, 144, 245, 176, 248, 150, 14, 166, 161, 27, 205, 54, 253];
    const CHALLENGE_HASH: [u8; 32] = [32, 40, 248, 44, 225, 214, 0, 161, 197, 113, 178, 102, 73, 82, 63, 107, 176, 196, 21, 63, 254, 173, 161, 2, 166, 207, 60, 95, 239, 86, 9, 61];
    const SIGNATURE_DEVICE: [u8; 64] = [158, 220, 195, 163, 254, 53, 31, 79, 93, 163, 186, 252, 237, 103, 156, 223, 136, 147, 82, 111, 23, 40, 119, 72, 193, 19, 195, 44, 205, 224, 216, 21, 89, 85, 244, 178, 26, 139, 114, 226, 168, 180, 27, 10, 172, 160, 163, 102, 37, 212, 141, 92, 74, 210, 230, 158, 155, 70, 227, 32, 219, 110, 231, 152];
    const REVOCATION_LIST: [u8; 208] = [0, 0, 0, 0, 0, 19, 72, 0, 0, 0, 0, 0, 105, 12, 216, 192, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 105, 77, 116, 25, 18, 94, 156, 30, 23, 239, 142, 116, 96, 124, 232, 193, 10, 107, 181, 126, 56, 6, 22, 52, 44, 138, 27, 170, 216, 208, 91, 199, 107, 36, 99, 121, 197, 183, 57, 215, 181, 235, 25, 149, 0, 188, 92, 158, 224, 75, 54, 4, 35, 137, 54, 24, 74, 91, 228, 185, 108, 203, 18, 236];

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

    #[test]
    #[serial]
    fn test_noir_issuer_signature() {
        let low_memory_mode = false;
        let on_chain = true; // on_chain (uses Keccak for Solidity compatibility)
        let vk = get_noir_verification_key(
            ISSUER_SIGNATURE_CIRCUIT_FILE.to_string().clone(),
            Some(ISSUER_SIGNATURE_SRS_FILE.to_string().clone()),
            on_chain,
            low_memory_mode,
        )
        .unwrap();
        let input_json: serde_json::Value = json!({
            "credential_string": &CREDENTIAL_STRING,
            "signature_issuer": &SIGNATURE_ISSUER[..],
            "pubkey_issuer_x": &PUBKEY_ISSUER_X[..],
            "pubkey_issuer_y": &PUBKEY_ISSUER_Y[..],
        });
        let proof = generate_noir_proof(
            ISSUER_SIGNATURE_CIRCUIT_FILE.to_string().clone(),
            Some(ISSUER_SIGNATURE_SRS_FILE.to_string().clone()),
            &input_json.to_string(),
            on_chain,
            vk.clone(),
            low_memory_mode,
            "IssuerSignature", // circuit type
        )
        .unwrap();

        let valid = verify_noir_proof(
            ISSUER_SIGNATURE_CIRCUIT_FILE.to_string().clone(),
            proof,
            true, // on_chain (uses Keccak for Solidity compatibility)
            vk,
            false, // low_memory_mode
        )
        .unwrap();
        assert!(valid);
    }

    #[test]
    #[serial]
    fn test_noir_age_verification() {
        let low_memory_mode = false;
        let on_chain = true; // on_chain (uses Keccak for Solidity compatibility)
        let vk = get_noir_verification_key(
            AGE_VERIFICATION_CIRCUIT_FILE.to_string().clone(),
            Some(AGE_VERIFICATION_SRS_FILE.to_string().clone()),
            on_chain,
            low_memory_mode,
        )
        .unwrap();
        let input_json: serde_json::Value = json!({
            "credential_string": &CREDENTIAL_STRING,
            "current_date": &CURRENT_DATE,
        });
        let proof = generate_noir_proof(
            AGE_VERIFICATION_CIRCUIT_FILE.to_string().clone(),
            Some(AGE_VERIFICATION_SRS_FILE.to_string().clone()),
            &input_json.to_string(),
            on_chain,
            vk.clone(),
            low_memory_mode,
            "AgeVerification", // circuit type
        )
        .unwrap();

        let valid = verify_noir_proof(
            AGE_VERIFICATION_CIRCUIT_FILE.to_string().clone(),
            proof,
            true, // on_chain (uses Keccak for Solidity compatibility)
            vk,
            false, // low_memory_mode
        )
        .unwrap();
        assert!(valid);
    }

    #[test]
    #[serial]
    fn test_noir_non_revocation() {
        let low_memory_mode = false;
        let on_chain = true; // on_chain (uses Keccak for Solidity compatibility)
        let vk = get_noir_verification_key(
            NON_REVOCATION_CIRCUIT_FILE.to_string().clone(),
            Some(NON_REVOCATION_SRS_FILE.to_string().clone()),
            on_chain,
            low_memory_mode,
        )
        .unwrap();
        let input_json: serde_json::Value = json!({
            "credential_string": &CREDENTIAL_STRING,
            "current_date": &CURRENT_DATE,
            "revocation_list": &REVOCATION_LIST[..],
            "pubkey_issuer_x": &PUBKEY_ISSUER_X[..],
            "pubkey_issuer_y": &PUBKEY_ISSUER_Y[..],
        });
        let proof = generate_noir_proof(
            NON_REVOCATION_CIRCUIT_FILE.to_string().clone(),
            Some(NON_REVOCATION_SRS_FILE.to_string().clone()),
            &input_json.to_string(),
            on_chain,
            vk.clone(),
            low_memory_mode,
            "NonRevocation", // circuit type
        )
        .unwrap();

        let valid = verify_noir_proof(
            NON_REVOCATION_CIRCUIT_FILE.to_string().clone(),
            proof,
            true, // on_chain (uses Keccak for Solidity compatibility)
            vk,
            false, // low_memory_mode
        )
        .unwrap();
        assert!(valid);
    }

    #[test]
    #[serial]
    fn test_noir_full_proof() {
        let low_memory_mode = false;
        let on_chain = true; // on_chain (uses Keccak for Solidity compatibility)
        let vk = get_noir_verification_key(
            FULL_PROOF_CIRCUIT_FILE.to_string().clone(),
            Some(FULL_PROOF_SRS_FILE.to_string().clone()),
            on_chain,
            low_memory_mode,
        )
        .unwrap();
        let input_json: serde_json::Value = json!({
            "credential_string": &CREDENTIAL_STRING,
            "current_date": &CURRENT_DATE,
            "revocation_list": &REVOCATION_LIST[..],
            "pubkey_issuer_x": &PUBKEY_ISSUER_X[..],
            "pubkey_issuer_y": &PUBKEY_ISSUER_Y[..],
            "signature_device": &SIGNATURE_DEVICE[..],
            "challenge_hash": &CHALLENGE_HASH[..],
            "signature_issuer": &SIGNATURE_ISSUER[..],
        });
        let proof = generate_noir_proof(
            FULL_PROOF_CIRCUIT_FILE.to_string().clone(),
            Some(FULL_PROOF_SRS_FILE.to_string().clone()),
            &input_json.to_string(),
            on_chain,
            vk.clone(),
            low_memory_mode,
            "FullProof", // circuit type
        )
        .unwrap();

        let valid = verify_noir_proof(
            FULL_PROOF_CIRCUIT_FILE.to_string().clone(),
            proof,
            true, // on_chain (uses Keccak for Solidity compatibility)
            vk,
            false, // low_memory_mode
        )
        .unwrap();
        assert!(valid);
    }
}

