use noir_rs::{
    barretenberg::{
        prove::{prove_ultra_honk, prove_ultra_honk_keccak},
        srs::setup_srs_from_bytecode,
        verify::{
            get_ultra_honk_keccak_verification_key, get_ultra_honk_verification_key,
            verify_ultra_honk, verify_ultra_honk_keccak,
        },
    },
    acir::{native_types::{WitnessMap}, FieldElement},
};
use noirc_abi::{Abi, AbiParameter, AbiType, AbiVisibility, Sign};
use noirc_abi::input_parser::json::parse_json;
use serde_json::{Value, json};

use crate::MoproError;

/// Generates a Noir proof with automatic hash function selection
///
/// This is the main proof generation function that automatically chooses
/// the appropriate hash function based on the intended use case:
///
/// - `on_chain = true`: Uses Keccak hash for Solidity verifier compatibility
/// - `on_chain = false`: Uses Poseidon hash for better performance
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn generate_noir_proof(
    circuit_path: String,
    srs_path: Option<String>,
    input: &str,
    on_chain: bool,
    vk: Vec<u8>,
    low_memory_mode: bool,
    circuit: &str,
) -> Result<Vec<u8>, MoproError> {
    let abi = match circuit {
        "HolderBinding" => Ok(get_holder_binding_abi()),
        _ => Err("unknown circuit type"),
    }.unwrap();
    let witness = build_witness(&input, abi).unwrap();
    let res = if on_chain {
        generate_noir_proof_with_keccak(circuit_path, srs_path, witness, false, vk, low_memory_mode)
    } else {
        generate_noir_proof_with_poseidon(circuit_path, srs_path, witness, vk, low_memory_mode)
    };

    res.map_err(|e| MoproError::NoirError(format!("Generate Proof error: {}", e)))
}

/// Verifies a Noir proof with automatic hash function selection
///
/// This function automatically uses the correct verification method based
/// on how the proof was generated:
///
/// - `on_chain = true`: Verifies Keccak-based proof (Solidity compatible)
/// - `on_chain = false`: Verifies Poseidon-based proof (performance optimized)
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn verify_noir_proof(
    circuit_path: String,
    proof: Vec<u8>,
    on_chain: bool,
    vk: Vec<u8>,
    low_memory_mode: bool,
) -> Result<bool, MoproError> {
    if on_chain {
        Ok(verify_noir_proof_with_keccak(
            circuit_path,
            proof,
            false,
            vk,
            low_memory_mode,
        ))
    } else {
        Ok(verify_noir_proof_with_poseidon(
            circuit_path,
            proof,
            vk,
            low_memory_mode,
        ))
    }
}

/// Generates a verification key with automatic hash function selection
///
/// This function automatically chooses the appropriate hash function based
/// on the intended use case:
///
/// - `on_chain = true`: Uses Keccak hash for Solidity verifier compatibility
/// - `on_chain = false`: Uses Poseidon hash fotr better performance
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn get_noir_verification_key(
    circuit_path: String,
    srs_path: Option<String>,
    on_chain: bool,
    low_memory_mode: bool,
) -> Result<Vec<u8>, MoproError> {
    let res = if on_chain {
        get_noir_verification_keccak_key(circuit_path, srs_path, false, low_memory_mode)
    } else {
        get_noir_verification_poseidon_key(circuit_path, srs_path, low_memory_mode)
    };

    res.map_err(|e| MoproError::NoirError(format!("Get Verification Key error: {}", e)))
}

/// Generates a Noir proof using Poseidon as oracle hash with a pre-compiled witness
///
/// This function uses the Poseidon hash function for better performance.
/// However, proofs generated with Poseidon cannot be verified
/// on-chain with Solidity verifiers.
///
/// Use this for off-chain verification or when maximum performance is needed.
fn generate_noir_proof_with_poseidon(
    circuit_path: String,
    srs_path: Option<String>,
    witness: WitnessMap<FieldElement>,
    vk: Vec<u8>,
    low_memory_mode: bool,
) -> Result<Vec<u8>, String> {
    let circuit_bytecode = get_bytecode(circuit_path);
    setup_srs_from_bytecode(circuit_bytecode.as_str(), srs_path.as_deref(), false).unwrap();

    prove_ultra_honk(circuit_bytecode.as_str(), witness, vk, low_memory_mode)
}

/// Verifies a Noir proof generated with Poseidon as oracle hash
///
/// This function verifies proofs that were generated using the Poseidon hash.
/// It cannot verify proofs intended for on-chain verification with Solidity verifiers.
pub fn verify_noir_proof_with_poseidon(
    circuit_path: String,
    proof: Vec<u8>,
    vk: Vec<u8>,
    _low_memory_mode: bool,
) -> bool {
    let _circuit_bytecode = get_bytecode(circuit_path);
    verify_ultra_honk(proof, vk).unwrap()
}

/// Generates a verification key for Poseidon-based Noir proofs
///
/// This verification key can only be used to verify proofs generated
/// with the Poseidon hash function (off-chain proofs).
fn get_noir_verification_poseidon_key(
    circuit_path: String,
    srs_path: Option<String>,
    low_memory_mode: bool,
) -> Result<Vec<u8>, String> {
    let circuit_bytecode = get_bytecode(circuit_path);

    setup_srs_from_bytecode(circuit_bytecode.as_str(), srs_path.as_deref(), false).unwrap();

    let vk = get_ultra_honk_verification_key(circuit_bytecode.as_str(), low_memory_mode).unwrap();
    Ok(vk)
}

/// Generates a Noir proof using Keccak as oracle hash with a pre-compiled witness
///
/// This function uses the Keccak hash function which is required for
/// generating proofs that can be verified on-chain with Solidity verifiers.
/// While slightly less performant than Poseidon, it enables on-chain verification.
///
/// Use this when you need to verify proofs on Ethereum or other EVM chains.
fn generate_noir_proof_with_keccak(
    circuit_path: String,
    srs_path: Option<String>,
    witness: WitnessMap<FieldElement>,
    disable_zk: bool,
    vk: Vec<u8>,
    low_memory_mode: bool,
) -> Result<Vec<u8>, String> {
    let circuit_bytecode = get_bytecode(circuit_path);
    setup_srs_from_bytecode(circuit_bytecode.as_str(), srs_path.as_deref(), false).unwrap();

    prove_ultra_honk_keccak(
        circuit_bytecode.as_str(),
        witness,
        vk,
        disable_zk,
        low_memory_mode,
    )
}

/// Verifies a Noir proof generated with Keccak as oracle hash
///
/// This function verifies proofs that were generated using the Keccak hash,
/// which are compatible with Solidity verifiers for on-chain verification.
fn verify_noir_proof_with_keccak(
    circuit_path: String,
    proof: Vec<u8>,
    disable_zk: bool,
    vk: Vec<u8>,
    _low_memory_mode: bool,
) -> bool {
    let _circuit_bytecode = get_bytecode(circuit_path);
    verify_ultra_honk_keccak(proof, vk, disable_zk).unwrap()
}

/// Generates a verification key for Keccak-based Noir proofs
///
/// This verification key can be used to verify proofs generated with
/// the Keccak hash function, and is compatible with Solidity verifiers
/// for on-chain verification.
fn get_noir_verification_keccak_key(
    circuit_path: String,
    srs_path: Option<String>,
    disable_zk: bool,
    low_memory_mode: bool,
) -> Result<Vec<u8>, String> {
    let circuit_bytecode = get_bytecode(circuit_path);

    // Setup the SRS
    setup_srs_from_bytecode(circuit_bytecode.as_str(), srs_path.as_deref(), false).unwrap();

    // Set up the witness
    let vk = get_ultra_honk_keccak_verification_key(
        circuit_bytecode.as_str(),
        disable_zk,
        low_memory_mode,
    )
    .unwrap();
    Ok(vk)
}

fn get_bytecode(circuit_path: String) -> String {
    // Read the JSON manifest of the circuit
    let circuit_txt = std::fs::read_to_string(circuit_path).unwrap();
    let circuit: serde_json::Value = serde_json::from_str(&circuit_txt).unwrap();

    circuit["bytecode"].as_str().unwrap().to_string()
}

pub fn get_holder_binding_abi() -> Abi {
    let parameters= vec![
        AbiParameter {
            name: "credential_string".to_string(),
            typ: AbiType::String{ length: 218},
            visibility: AbiVisibility::Private,
        },
        AbiParameter {
            name: "signature_device".to_string(),
            typ: AbiType::Array{ length: 64, typ: Box::new(AbiType::Integer{ sign: Sign::Unsigned, width: 8 })},
            visibility: AbiVisibility::Private,
        },
        AbiParameter {
            name: "challenge_hash".to_string(),
            typ: AbiType::Array{ length: 32, typ: Box::new(AbiType::Integer{ sign: Sign::Unsigned, width: 8 })},
            visibility: AbiVisibility::Private,
        },
    ];
    Abi {
        parameters: parameters,
        return_type: None,
        error_types: Default::default(),
    }
}

pub fn build_witness(
    input: &str,
    abi: Abi
) -> Result<WitnessMap<FieldElement>, String> {
    let input_map = parse_json(input, &abi).unwrap();
    let witness_map = abi.encode(&input_map, None).unwrap();

    Ok(witness_map)
}

#[cfg(test)]
mod tests {
    const HOLDER_BINDING_CIRCUIT_FILE: &str = "./test-vectors/noir/noir_c03_holder_binding.json";
    const HOLDER_BINDING_SRS_FILE: &str = "./test-vectors/noir/noir_c03_holder_binding.srs";

    const CREDENTIAL_STRING: &str = "Alice                           Smith                           09583416008caa0593dfd6510b118188f28e623eec9ffb719a4ecbc689a19d7de57b2a8182876001d8323c4a4cd8991c1cea15d4dbc12b463ac7b6d1e906c294c68f1766f70000000000134a37";
    const SIGNATURE_DEVICE: [u8; 64] = [171, 194, 24, 110, 235, 188, 255, 0, 116, 193, 34, 12, 208, 148, 158, 205, 151, 28, 248, 111, 202, 38, 199, 141, 79, 156, 109, 12, 29, 34, 145, 2, 94, 91, 197, 154, 1, 195, 92, 33, 10, 251, 17, 202, 101, 53, 119, 226, 18, 31, 60, 80, 244, 59, 167, 219, 61, 41, 116, 98, 34, 34, 134, 240];
    const CHALLENGE_HASH: [u8; 32] = [0, 138, 146, 177, 229, 156, 197, 31, 176, 9, 150, 122, 223, 240, 132, 57, 241, 241, 99, 238, 181, 138, 146, 139, 55, 61, 55, 61, 150, 81, 25, 39];

    use super::*;

    #[test]
    #[serial_test::serial]
    fn test_proof_holder_binding() {
        let low_memory_mode = false;
        let input_json: serde_json::Value = json!({
            "credential_string": &CREDENTIAL_STRING,
            "signature_device": &SIGNATURE_DEVICE[..],
            "challenge_hash": &CHALLENGE_HASH[..],
        });
        let abi = get_holder_binding_abi();
        let witness = build_witness(&input_json.to_string(), abi).unwrap();
        let vk = get_noir_verification_poseidon_key(
            HOLDER_BINDING_CIRCUIT_FILE.to_string(),
            Some(HOLDER_BINDING_SRS_FILE.to_string()),
            low_memory_mode,
        )
        .unwrap();
        let proof = generate_noir_proof_with_poseidon(
            HOLDER_BINDING_CIRCUIT_FILE.to_string(),
            Some(HOLDER_BINDING_SRS_FILE.to_string()),
            witness,
            vk.clone(),
            low_memory_mode,
            )
            .unwrap();
        assert!(verify_noir_proof_with_poseidon(
            HOLDER_BINDING_CIRCUIT_FILE.to_string(),
            proof,
            vk,
            low_memory_mode,
        ));
    }

    #[test]
    #[serial_test::serial]
    fn test_proof_holder_binding_low_memory() {
        let low_memory_mode = true;
        let input_json: serde_json::Value = json!({
            "credential_string": &CREDENTIAL_STRING,
            "signature_device": &SIGNATURE_DEVICE[..],
            "challenge_hash": &CHALLENGE_HASH[..],
        });
        let abi = get_holder_binding_abi();
        let witness = build_witness(&input_json.to_string(), abi).unwrap();
        let vk = get_noir_verification_poseidon_key(
            HOLDER_BINDING_CIRCUIT_FILE.to_string(),
            Some(HOLDER_BINDING_SRS_FILE.to_string()),
            low_memory_mode,
        )
        .unwrap();
        let proof = generate_noir_proof_with_poseidon(
            HOLDER_BINDING_CIRCUIT_FILE.to_string(),
            Some(HOLDER_BINDING_SRS_FILE.to_string()),
            witness,
            vk.clone(),
            low_memory_mode,
            )
            .unwrap();
        assert!(verify_noir_proof_with_poseidon(
            HOLDER_BINDING_CIRCUIT_FILE.to_string(),
            proof,
            vk,
            low_memory_mode,
        ));
    }

    #[test]
    #[serial_test::serial]
    fn test_proof_holder_binding_without_srs_path() {
        let low_memory_mode = false;
        let input_json: serde_json::Value = json!({
            "credential_string": &CREDENTIAL_STRING,
            "signature_device": &SIGNATURE_DEVICE[..],
            "challenge_hash": &CHALLENGE_HASH[..],
        });
        let abi = get_holder_binding_abi();
        let witness = build_witness(&input_json.to_string(), abi).unwrap();
        let vk = get_noir_verification_poseidon_key(
            HOLDER_BINDING_CIRCUIT_FILE.to_string(),
            None,
            low_memory_mode,
        )
        .unwrap();
        let proof = generate_noir_proof_with_poseidon(
            HOLDER_BINDING_CIRCUIT_FILE.to_string(),
            None,
            witness,
            vk.clone(),
            low_memory_mode,
            )
            .unwrap();
        assert!(verify_noir_proof_with_poseidon(
            HOLDER_BINDING_CIRCUIT_FILE.to_string(),
            proof,
            vk,
            low_memory_mode,
        ));
    }

    #[test]
    #[serial_test::serial]
    fn test_keccak_proof_holder_binding() {
        let low_memory_mode = false;
        let disable_zk = false;
        let input_json: serde_json::Value = json!({
            "credential_string": &CREDENTIAL_STRING,
            "signature_device": &SIGNATURE_DEVICE[..],
            "challenge_hash": &CHALLENGE_HASH[..],
        });
        let abi = get_holder_binding_abi();
        let witness = build_witness(&input_json.to_string(), abi).unwrap();
        let vk = get_noir_verification_keccak_key(
            HOLDER_BINDING_CIRCUIT_FILE.to_string(),
            Some(HOLDER_BINDING_SRS_FILE.to_string()),
            disable_zk,
            low_memory_mode,
        )
        .unwrap();
        let proof = generate_noir_proof_with_keccak(
            HOLDER_BINDING_CIRCUIT_FILE.to_string(),
            Some(HOLDER_BINDING_SRS_FILE.to_string()),
            witness,
            disable_zk,
            vk.clone(),
            low_memory_mode,
        )
        .unwrap();
        assert!(verify_noir_proof_with_keccak(
            HOLDER_BINDING_CIRCUIT_FILE.to_string(),
            proof,
            disable_zk,
            vk,
            low_memory_mode,
        ));
    }

    #[test]
    #[serial_test::serial]
    fn test_keccak_proof_holder_binding_disable_zk() {
        let low_memory_mode = false;
        let disable_zk = true;
        let input_json: serde_json::Value = json!({
            "credential_string": &CREDENTIAL_STRING,
            "signature_device": &SIGNATURE_DEVICE[..],
            "challenge_hash": &CHALLENGE_HASH[..],
        });
        let abi = get_holder_binding_abi();
        let witness = build_witness(&input_json.to_string(), abi).unwrap();
        let vk = get_noir_verification_keccak_key(
            HOLDER_BINDING_CIRCUIT_FILE.to_string(),
            Some(HOLDER_BINDING_SRS_FILE.to_string()),
            disable_zk,
            low_memory_mode,
        )
        .unwrap();
        let proof = generate_noir_proof_with_keccak(
            HOLDER_BINDING_CIRCUIT_FILE.to_string(),
            Some(HOLDER_BINDING_SRS_FILE.to_string()),
            witness,
            disable_zk,
            vk.clone(),
            low_memory_mode,
        )
        .unwrap();
        assert!(verify_noir_proof_with_keccak(
            HOLDER_BINDING_CIRCUIT_FILE.to_string(),
            proof,
            disable_zk,
            vk,
            low_memory_mode,
        ));
    }

    #[test]
    #[serial_test::serial]
    fn test_keccak_proof_holder_binding_low_memory() {
        let low_memory_mode = true;
        let disable_zk = false;
        let input_json: serde_json::Value = json!({
            "credential_string": &CREDENTIAL_STRING,
            "signature_device": &SIGNATURE_DEVICE[..],
            "challenge_hash": &CHALLENGE_HASH[..],
        });
        let abi = get_holder_binding_abi();
        let witness = build_witness(&input_json.to_string(), abi).unwrap();
        let vk = get_noir_verification_keccak_key(
            HOLDER_BINDING_CIRCUIT_FILE.to_string(),
            Some(HOLDER_BINDING_SRS_FILE.to_string()),
            disable_zk,
            low_memory_mode,
        )
        .unwrap();
        let proof = generate_noir_proof_with_keccak(
            HOLDER_BINDING_CIRCUIT_FILE.to_string(),
            Some(HOLDER_BINDING_SRS_FILE.to_string()),
            witness,
            disable_zk,
            vk.clone(),
            low_memory_mode,
        )
        .unwrap();
        assert!(verify_noir_proof_with_keccak(
            HOLDER_BINDING_CIRCUIT_FILE.to_string(),
            proof,
            disable_zk,
            vk,
            low_memory_mode,
        ));
    }

// XXX does not pass
//    #[test]
//    #[serial_test::serial]
//    fn test_keccak_proof_holder_binding_with_vk() {
//        let low_memory_mode = false;
//        let disable_zk = false;
//        let input_json: serde_json::Value = json!({
//            "credential_string": &CREDENTIAL_STRING,
//            "signature_device": &SIGNATURE_DEVICE[..],
//            "challenge_hash": &CHALLENGE_HASH[..],
//        });
//        let abi = get_holder_binding_abi();
//        let witness = build_witness(&input_json.to_string(), abi).unwrap();
//        let vk = std::fs::read(HOLDER_BINDING_VK_FILE).unwrap();
//        let proof = generate_noir_proof_with_keccak(
//            HOLDER_BINDING_CIRCUIT_FILE.to_string(),
//            Some(HOLDER_BINDING_SRS_FILE.to_string()),
//            witness,
//            disable_zk,
//            vk.clone(),
//            low_memory_mode,
//        )
//        .unwrap();
//        let is_valid = verify_noir_proof_with_keccak(
//            HOLDER_BINDING_CIRCUIT_FILE.to_string(),
//            proof.clone(),
//            disable_zk,
//            vk.clone(),
//            low_memory_mode,
//        );
//        assert!(is_valid);
//    }

    #[test]
    #[serial_test::serial]
    fn test_get_noir_verification_poseidon_key() {
        let vk = get_noir_verification_poseidon_key(
            HOLDER_BINDING_CIRCUIT_FILE.to_string(),
            Some(HOLDER_BINDING_SRS_FILE.to_string()),
            false,
        );
        assert!(vk.is_ok());
        assert!(!vk.unwrap().is_empty());
    }

// XXX does not pass
//    #[test]
//    #[serial_test::serial]
//    fn test_noir_proof_with_poseidon_and_vk() {
//        let low_memory_mode = false;
//        let input_json: serde_json::Value = json!({
//            "credential_string": &CREDENTIAL_STRING,
//            "signature_device": &SIGNATURE_DEVICE[..],
//            "challenge_hash": &CHALLENGE_HASH[..],
//        });
//        let abi = get_holder_binding_abi();
//        let witness = build_witness(&input_json.to_string(), abi).unwrap();
//        let vk = std::fs::read(HOLDER_BINDING_VK_FILE).unwrap();
//        let proof = generate_noir_proof_with_poseidon(
//            HOLDER_BINDING_CIRCUIT_FILE.to_string(),
//            Some(HOLDER_BINDING_SRS_FILE.to_string()),
//            witness,
//            vk.clone(),
//            low_memory_mode,
//        )
//        .unwrap();
//        let is_valid = verify_noir_proof_with_poseidon(
//            HOLDER_BINDING_CIRCUIT_FILE.to_string(),
//            proof.clone(),
//            vk.clone(),
//            low_memory_mode,
//        );
//        assert!(is_valid);
//    }

    #[test]
    #[serial_test::serial]
    fn test_high_level_noir_proof_poseidon() {
        let on_chain = false;
        let low_memory_mode = false;
        let input_json: serde_json::Value = json!({
            "credential_string": &CREDENTIAL_STRING,
            "signature_device": &SIGNATURE_DEVICE[..],
            "challenge_hash": &CHALLENGE_HASH[..],
        });
        let vk = get_noir_verification_poseidon_key(
            HOLDER_BINDING_CIRCUIT_FILE.to_string(),
            Some(HOLDER_BINDING_SRS_FILE.to_string()),
            false,
        )
        .unwrap();
        let proof = generate_noir_proof(
            HOLDER_BINDING_CIRCUIT_FILE.to_string(),
            Some(HOLDER_BINDING_SRS_FILE.to_string()),
            &input_json.to_string(),
            on_chain,
            vk.clone(),
            low_memory_mode,
            "HolderBinding",
        )
        .unwrap();
        let is_valid = verify_noir_proof(
            HOLDER_BINDING_CIRCUIT_FILE.to_string(),
            proof,
            on_chain,
            vk,
            low_memory_mode,
        )
        .unwrap();
        assert!(is_valid);
    }

    #[test]
    #[serial_test::serial]
    fn test_high_level_noir_proof_keccak() {
        let on_chain = true;
        let low_memory_mode = false;
        let disable_zk = false;
        let input_json: serde_json::Value = json!({
            "credential_string": &CREDENTIAL_STRING,
            "signature_device": &SIGNATURE_DEVICE[..],
            "challenge_hash": &CHALLENGE_HASH[..],
        });
        let vk = get_noir_verification_keccak_key(
            HOLDER_BINDING_CIRCUIT_FILE.to_string(),
            Some(HOLDER_BINDING_SRS_FILE.to_string()),
            disable_zk,
            low_memory_mode,
        )
        .unwrap();
        let proof = generate_noir_proof(
            HOLDER_BINDING_CIRCUIT_FILE.to_string(),
            Some(HOLDER_BINDING_SRS_FILE.to_string()),
            &input_json.to_string(),
            on_chain,
            vk.clone(),
            low_memory_mode,
            "HolderBinding",
        )
        .unwrap();
        let is_valid =
            verify_noir_proof(HOLDER_BINDING_CIRCUIT_FILE.to_string(), proof, on_chain, vk, low_memory_mode)
                .unwrap();
        assert!(is_valid);
    }

// XXX does not pass
//    #[test]
//    #[serial_test::serial]
//    fn test_high_level_noir_proof_poseidon_with_vk() {
//        let on_chain = false;
//        let low_memory_mode = false;
//        let input_json: serde_json::Value = json!({
//            "credential_string": &CREDENTIAL_STRING,
//            "signature_device": &SIGNATURE_DEVICE[..],
//            "challenge_hash": &CHALLENGE_HASH[..],
//        });
//        let vk = std::fs::read(HOLDER_BINDING_VK_FILE).unwrap();
//        let proof = generate_noir_proof(
//            HOLDER_BINDING_CIRCUIT_FILE.to_string(),
//            Some(HOLDER_BINDING_SRS_FILE.to_string()),
//            &input_json.to_string(),
//            on_chain,
//            vk.clone(),
//            low_memory_mode,
//            "HolderBinding",
//        )
//        .unwrap();
//        let is_valid = verify_noir_proof(
//            HOLDER_BINDING_CIRCUIT_FILE.to_string(),
//            proof,
//            on_chain,
//            vk,
//            low_memory_mode,
//        )
//        .unwrap();
//        assert!(is_valid);
//    }

// XXX does not pass
//    #[test]
//    #[serial_test::serial]
//    fn test_high_level_noir_proof_keccak_with_vk() {
//        let on_chain = true;
//        let low_memory_mode = false;
//        let input_json: serde_json::Value = json!({
//            "credential_string": &CREDENTIAL_STRING,
//            "signature_device": &SIGNATURE_DEVICE[..],
//            "challenge_hash": &CHALLENGE_HASH[..],
//        });
//        let vk = std::fs::read(HOLDER_BINDING_VK_FILE).unwrap();
//        let proof = generate_noir_proof(
//            HOLDER_BINDING_CIRCUIT_FILE.to_string(),
//            Some(HOLDER_BINDING_SRS_FILE.to_string()),
//            &input_json.to_string(),
//            on_chain,
//            vk.clone(),
//            low_memory_mode,
//            "HolderBinding",
//        )
//        .unwrap();
//        let is_valid =
//            verify_noir_proof(HOLDER_BINDING_CIRCUIT_FILE.to_string(), proof, on_chain, vk, low_memory_mode)
//                .unwrap();
//        assert!(is_valid);
//    }


    #[test]
    #[serial_test::serial]
    fn test_get_noir_verification_key_poseidon() {
        let vk = get_noir_verification_key(
            HOLDER_BINDING_CIRCUIT_FILE.to_string(),
            Some(HOLDER_BINDING_SRS_FILE.to_string()),
            false, // off-chain, uses Poseidon
            false,
        );
        assert!(vk.is_ok());
        assert!(!vk.unwrap().is_empty());
    }

    #[test]
    #[serial_test::serial]
    fn test_get_noir_verification_key_keccak() {
        let vk = get_noir_verification_key(
            HOLDER_BINDING_CIRCUIT_FILE.to_string(),
            Some(HOLDER_BINDING_SRS_FILE.to_string()),
            true, // on-chain, uses Keccak
            false,
        );
        assert!(vk.is_ok());
        assert!(!vk.unwrap().is_empty());
    }

    #[test]
    #[serial_test::serial]
    fn test_noir_app_macro() {
        let low_memory_mode = false;
        let input_json: serde_json::Value = json!({
            "credential_string": &CREDENTIAL_STRING,
            "signature_device": &SIGNATURE_DEVICE[..],
            "challenge_hash": &CHALLENGE_HASH[..],
        });
        let vk_offchain = get_noir_verification_key(
            HOLDER_BINDING_CIRCUIT_FILE.to_string(),
            Some(HOLDER_BINDING_SRS_FILE.to_string()),
            false,
            low_memory_mode,
        )
        .unwrap();
        let vk_onchain = get_noir_verification_key(
            HOLDER_BINDING_CIRCUIT_FILE.to_string(),
            Some(HOLDER_BINDING_SRS_FILE.to_string()),
            true,
            low_memory_mode,
        )
        .unwrap();
        let proof_offchain = generate_noir_proof(
            HOLDER_BINDING_CIRCUIT_FILE.to_string(),
            Some(HOLDER_BINDING_SRS_FILE.to_string()),
            &input_json.to_string(),
            false,
            vk_offchain.clone(),
            low_memory_mode,
            "HolderBinding",
        );
        let proof_onchain = generate_noir_proof(
            HOLDER_BINDING_CIRCUIT_FILE.to_string(),
            Some(HOLDER_BINDING_SRS_FILE.to_string()),
            &input_json.to_string(),
            true,
            vk_onchain.clone(),
            low_memory_mode,
            "HolderBinding",
        );

        assert!(proof_offchain.is_ok());
        assert!(proof_onchain.is_ok());
        let proof_offchain = proof_offchain.unwrap();
        let proof_onchain = proof_onchain.unwrap();

        let verify_result_offchain = verify_noir_proof(
            HOLDER_BINDING_CIRCUIT_FILE.to_string(),
            proof_offchain.clone(),
            false,
            vk_offchain,
            low_memory_mode,
        );
        let verify_result_onchain = verify_noir_proof(
            HOLDER_BINDING_CIRCUIT_FILE.to_string(),
            proof_onchain.clone(),
            true,
            vk_onchain,
            low_memory_mode,
        );

        assert!(verify_result_offchain.is_ok());
        assert!(verify_result_offchain.unwrap());
        assert!(verify_result_onchain.is_ok());
        assert!(verify_result_onchain.unwrap());
    }
}
