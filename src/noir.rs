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
    let abi = get_circuit_abi(circuit).unwrap();
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

fn get_circuit_abi(circuit: &str) -> Result<Abi, String> {
    match circuit {
        "HolderBinding" => Ok(get_holder_binding_abi()),
        "IssuerSignature" => Ok(get_issuer_signature_abi()),
        "AgeVerification" => Ok(get_age_verification_abi()),
        "NonRevocation" => Ok(get_non_revocation_abi()),
        "FullProof" => Ok(get_full_proof_abi()),
        "SwiyuJwt" => Ok(get_swiyu_jwt_abi()),
        _ => Err(format!("unknown circuit type: {circuit}")),
    }
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

pub fn get_issuer_signature_abi() -> Abi {
    let parameters= vec![
        AbiParameter {
            name: "credential_string".to_string(),
            typ: AbiType::String{ length: 218},
            visibility: AbiVisibility::Private,
        },
        AbiParameter {
            name: "signature_issuer".to_string(),
            typ: AbiType::Array{ length: 64, typ: Box::new(AbiType::Integer{ sign: Sign::Unsigned, width: 8 })},
            visibility: AbiVisibility::Private,
        },
        AbiParameter {
            name: "pubkey_issuer_x".to_string(),
            typ: AbiType::Array{ length: 32, typ: Box::new(AbiType::Integer{ sign: Sign::Unsigned, width: 8 })},
            visibility: AbiVisibility::Private,
        },
        AbiParameter {
            name: "pubkey_issuer_y".to_string(),
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

pub fn get_age_verification_abi() -> Abi {
    let parameters= vec![
        AbiParameter {
            name: "credential_string".to_string(),
            typ: AbiType::String{ length: 218},
            visibility: AbiVisibility::Private,
        },
        AbiParameter {
            name: "current_date".to_string(),
            typ: AbiType::Integer{ sign: Sign::Unsigned, width: 64 },
            visibility: AbiVisibility::Private,
        },
    ];
    Abi {
        parameters: parameters,
        return_type: None,
        error_types: Default::default(),
    }
}

pub fn get_non_revocation_abi() -> Abi {
    let parameters= vec![
        AbiParameter {
            name: "credential_string".to_string(),
            typ: AbiType::String{ length: 218},
            visibility: AbiVisibility::Private,
        },
        AbiParameter {
            name: "revocation_list".to_string(),
            typ: AbiType::Array{ length: 208, typ: Box::new(AbiType::Integer{ sign: Sign::Unsigned, width: 8 })},
            visibility: AbiVisibility::Private,
        },
        AbiParameter {
            name: "current_date".to_string(),
            typ: AbiType::Integer{ sign: Sign::Unsigned, width: 64 },
            visibility: AbiVisibility::Private,
        },
        AbiParameter {
            name: "pubkey_issuer_x".to_string(),
            typ: AbiType::Array{ length: 32, typ: Box::new(AbiType::Integer{ sign: Sign::Unsigned, width: 8 })},
            visibility: AbiVisibility::Private,
        },
        AbiParameter {
            name: "pubkey_issuer_y".to_string(),
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

pub fn get_full_proof_abi() -> Abi {
    let parameters= vec![
        AbiParameter {
            name: "credential_string".to_string(),
            typ: AbiType::String{ length: 218},
            visibility: AbiVisibility::Private,
        },
        AbiParameter {
            name: "revocation_list".to_string(),
            typ: AbiType::Array{ length: 208, typ: Box::new(AbiType::Integer{ sign: Sign::Unsigned, width: 8 })},
            visibility: AbiVisibility::Private,
        },
        AbiParameter {
            name: "signature_device".to_string(),
            typ: AbiType::Array{ length: 64, typ: Box::new(AbiType::Integer{ sign: Sign::Unsigned, width: 8 })},
            visibility: AbiVisibility::Private,
        },
        AbiParameter {
            name: "signature_issuer".to_string(),
            typ: AbiType::Array{ length: 64, typ: Box::new(AbiType::Integer{ sign: Sign::Unsigned, width: 8 })},
            visibility: AbiVisibility::Private,
        },
        AbiParameter {
            name: "challenge_hash".to_string(),
            typ: AbiType::Array{ length: 32, typ: Box::new(AbiType::Integer{ sign: Sign::Unsigned, width: 8 })},
            visibility: AbiVisibility::Private,
        },
        AbiParameter {
            name: "current_date".to_string(),
            typ: AbiType::Integer{ sign: Sign::Unsigned, width: 64 },
            visibility: AbiVisibility::Private,
        },
        AbiParameter {
            name: "pubkey_issuer_x".to_string(),
            typ: AbiType::Array{ length: 32, typ: Box::new(AbiType::Integer{ sign: Sign::Unsigned, width: 8 })},
            visibility: AbiVisibility::Private,
        },
        AbiParameter {
            name: "pubkey_issuer_y".to_string(),
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

pub fn get_swiyu_jwt_abi() -> Abi {
    let parameters = vec![
        AbiParameter {
            name: "payload".to_string(),
            typ: AbiType::Struct {
                path: "std::collections::bounded_vec::BoundedVec".to_string(),
                fields: vec![
                    (
                        "storage".to_string(),
                        AbiType::Array {
                            length: 2048,
                            typ: Box::new(AbiType::Integer { sign: Sign::Unsigned, width: 8 }),
                        },
                    ),
                    (
                        "len".to_string(),
                        AbiType::Integer { sign: Sign::Unsigned, width: 32 },
                    ),
                ],
            },
            visibility: AbiVisibility::Private,
        },
        AbiParameter {
            name: "jwt_signature".to_string(),
            typ: AbiType::Array { length: 64, typ: Box::new(AbiType::Integer { sign: Sign::Unsigned, width: 8 })},
            visibility: AbiVisibility::Private,
        },
        AbiParameter {
            name: "dob_salt".to_string(),
            typ: AbiType::Struct {
                path: "std::collections::bounded_vec::BoundedVec".to_string(),
                fields: vec![
                    (
                        "storage".to_string(),
                        AbiType::Array {
                            length: 32,
                            typ: Box::new(AbiType::Integer { sign: Sign::Unsigned, width: 8 }),
                        },
                    ),
                    (
                        "len".to_string(),
                        AbiType::Integer { sign: Sign::Unsigned, width: 32 },
                    ),
                ],
            },
            visibility: AbiVisibility::Private,
        },
        AbiParameter {
            name: "dob_value".to_string(),
            typ: AbiType::Struct {
                path: "std::collections::bounded_vec::BoundedVec".to_string(),
                fields: vec![
                    (
                        "storage".to_string(),
                        AbiType::Array {
                            length: 16,
                            typ: Box::new(AbiType::Integer { sign: Sign::Unsigned, width: 8 }),
                        },
                    ),
                    (
                        "len".to_string(),
                        AbiType::Integer { sign: Sign::Unsigned, width: 32 },
                    ),
                ],
            },
            visibility: AbiVisibility::Private,
        },
        AbiParameter {
            name: "dob_sd_offset".to_string(),
            typ: AbiType::Integer { sign: Sign::Unsigned, width: 32 },
            visibility: AbiVisibility::Private,
        },
        AbiParameter {
            name: "x_offset".to_string(),
            typ: AbiType::Integer { sign: Sign::Unsigned, width: 32 },
            visibility: AbiVisibility::Private,
        },
        AbiParameter {
            name: "y_offset".to_string(),
            typ: AbiType::Integer { sign: Sign::Unsigned, width: 32 },
            visibility: AbiVisibility::Private,
        },
        AbiParameter {
            name: "device_signature".to_string(),
            typ: AbiType::Array { length: 64, typ: Box::new(AbiType::Integer { sign: Sign::Unsigned, width: 8})},
            visibility: AbiVisibility::Private,
        },
        AbiParameter {
            name: "issuer_pub_x".to_string(),
            typ: AbiType::Array { length: 32, typ: Box::new(AbiType::Integer { sign: Sign::Unsigned, width: 8})},
            visibility: AbiVisibility::Public,
        },
        AbiParameter {
            name: "issuer_pub_y".to_string(),
            typ: AbiType::Array { length: 32, typ: Box::new(AbiType::Integer { sign: Sign::Unsigned, width: 8})},
            visibility: AbiVisibility::Public,
        },
        AbiParameter {
            name: "now_date".to_string(),
            typ: AbiType::Integer { sign: Sign::Unsigned, width: 32},
            visibility: AbiVisibility::Public,
        },
        AbiParameter {
            name: "challenge_nonce".to_string(),
            typ: AbiType::Array { length: 32, typ: Box::new(AbiType::Integer { sign: Sign::Unsigned, width: 8})},
            visibility: AbiVisibility::Public,
        },
    ];
    Abi {
        parameters,
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

    const SWIYU_JWT_CIRCUIT_FILE: &str = concat!(TEST_VECTORS!(), "noir_d10_swiyu_jwt.json");
    const SWIYU_JWT_SRS_FILE: &str = concat!(TEST_VECTORS!(), "noir_d10_swiyu_jwt.srs");

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

    #[test]
    #[serial_test::serial]
    fn test_proof_issuer_signature() {
        let low_memory_mode = false;
        let input_json: serde_json::Value = json!({
            "credential_string": &CREDENTIAL_STRING,
            "signature_issuer": &SIGNATURE_ISSUER[..],
            "pubkey_issuer_x": &PUBKEY_ISSUER_X[..],
            "pubkey_issuer_y": &PUBKEY_ISSUER_Y[..],
        });
        let abi = get_issuer_signature_abi();
        let witness = build_witness(&input_json.to_string(), abi).unwrap();
        let vk = get_noir_verification_poseidon_key(
            ISSUER_SIGNATURE_CIRCUIT_FILE.to_string(),
            Some(ISSUER_SIGNATURE_SRS_FILE.to_string()),
            low_memory_mode,
        )
        .unwrap();
        let proof = generate_noir_proof_with_poseidon(
            ISSUER_SIGNATURE_CIRCUIT_FILE.to_string(),
            Some(ISSUER_SIGNATURE_SRS_FILE.to_string()),
            witness,
            vk.clone(),
            low_memory_mode,
            )
            .unwrap();
        assert!(verify_noir_proof_with_poseidon(
            ISSUER_SIGNATURE_CIRCUIT_FILE.to_string(),
            proof,
            vk,
            low_memory_mode,
        ));
    }

    #[test]
    #[serial_test::serial]
    fn test_proof_issuer_signature_low_memory() {
        let low_memory_mode = true;
        let input_json: serde_json::Value = json!({
            "credential_string": &CREDENTIAL_STRING,
            "signature_issuer": &SIGNATURE_ISSUER[..],
            "pubkey_issuer_x": &PUBKEY_ISSUER_X[..],
            "pubkey_issuer_y": &PUBKEY_ISSUER_Y[..],
        });
        let abi = get_issuer_signature_abi();
        let witness = build_witness(&input_json.to_string(), abi).unwrap();
        let vk = get_noir_verification_poseidon_key(
            ISSUER_SIGNATURE_CIRCUIT_FILE.to_string(),
            Some(ISSUER_SIGNATURE_SRS_FILE.to_string()),
            low_memory_mode,
        )
        .unwrap();
        let proof = generate_noir_proof_with_poseidon(
            ISSUER_SIGNATURE_CIRCUIT_FILE.to_string(),
            Some(ISSUER_SIGNATURE_SRS_FILE.to_string()),
            witness,
            vk.clone(),
            low_memory_mode,
            )
            .unwrap();
        assert!(verify_noir_proof_with_poseidon(
            ISSUER_SIGNATURE_CIRCUIT_FILE.to_string(),
            proof,
            vk,
            low_memory_mode,
        ));
    }

    #[test]
    #[serial_test::serial]
    fn test_proof_issuer_signature_without_srs_path() {
        let low_memory_mode = false;
        let input_json: serde_json::Value = json!({
            "credential_string": &CREDENTIAL_STRING,
            "signature_issuer": &SIGNATURE_ISSUER[..],
            "pubkey_issuer_x": &PUBKEY_ISSUER_X[..],
            "pubkey_issuer_y": &PUBKEY_ISSUER_Y[..],
        });
        let abi = get_issuer_signature_abi();
        let witness = build_witness(&input_json.to_string(), abi).unwrap();
        let vk = get_noir_verification_poseidon_key(
            ISSUER_SIGNATURE_CIRCUIT_FILE.to_string(),
            None,
            low_memory_mode,
        )
        .unwrap();
        let proof = generate_noir_proof_with_poseidon(
            ISSUER_SIGNATURE_CIRCUIT_FILE.to_string(),
            None,
            witness,
            vk.clone(),
            low_memory_mode,
            )
            .unwrap();
        assert!(verify_noir_proof_with_poseidon(
            ISSUER_SIGNATURE_CIRCUIT_FILE.to_string(),
            proof,
            vk,
            low_memory_mode,
        ));
    }

    #[test]
    #[serial_test::serial]
    fn test_keccak_proof_issuer_signature() {
        let low_memory_mode = false;
        let disable_zk = false;
        let input_json: serde_json::Value = json!({
            "credential_string": &CREDENTIAL_STRING,
            "signature_issuer": &SIGNATURE_ISSUER[..],
            "pubkey_issuer_x": &PUBKEY_ISSUER_X[..],
            "pubkey_issuer_y": &PUBKEY_ISSUER_Y[..],
        });
        let abi = get_issuer_signature_abi();
        let witness = build_witness(&input_json.to_string(), abi).unwrap();
        let vk = get_noir_verification_keccak_key(
            ISSUER_SIGNATURE_CIRCUIT_FILE.to_string(),
            Some(ISSUER_SIGNATURE_SRS_FILE.to_string()),
            disable_zk,
            low_memory_mode,
        )
        .unwrap();
        let proof = generate_noir_proof_with_keccak(
            ISSUER_SIGNATURE_CIRCUIT_FILE.to_string(),
            Some(ISSUER_SIGNATURE_SRS_FILE.to_string()),
            witness,
            disable_zk,
            vk.clone(),
            low_memory_mode,
        )
        .unwrap();
        assert!(verify_noir_proof_with_keccak(
            ISSUER_SIGNATURE_CIRCUIT_FILE.to_string(),
            proof,
            disable_zk,
            vk,
            low_memory_mode,
        ));
    }

    #[test]
    #[serial_test::serial]
    fn test_keccak_proof_issuer_signature_disable_zk() {
        let low_memory_mode = false;
        let disable_zk = true;
        let input_json: serde_json::Value = json!({
            "credential_string": &CREDENTIAL_STRING,
            "signature_issuer": &SIGNATURE_ISSUER[..],
            "pubkey_issuer_x": &PUBKEY_ISSUER_X[..],
            "pubkey_issuer_y": &PUBKEY_ISSUER_Y[..],
        });
        let abi = get_issuer_signature_abi();
        let witness = build_witness(&input_json.to_string(), abi).unwrap();
        let vk = get_noir_verification_keccak_key(
            ISSUER_SIGNATURE_CIRCUIT_FILE.to_string(),
            Some(ISSUER_SIGNATURE_SRS_FILE.to_string()),
            disable_zk,
            low_memory_mode,
        )
        .unwrap();
        let proof = generate_noir_proof_with_keccak(
            ISSUER_SIGNATURE_CIRCUIT_FILE.to_string(),
            Some(ISSUER_SIGNATURE_SRS_FILE.to_string()),
            witness,
            disable_zk,
            vk.clone(),
            low_memory_mode,
        )
        .unwrap();
        assert!(verify_noir_proof_with_keccak(
            ISSUER_SIGNATURE_CIRCUIT_FILE.to_string(),
            proof,
            disable_zk,
            vk,
            low_memory_mode,
        ));
    }

    #[test]
    #[serial_test::serial]
    fn test_keccak_proof_issuer_signature_low_memory() {
        let low_memory_mode = true;
        let disable_zk = false;
        let input_json: serde_json::Value = json!({
            "credential_string": &CREDENTIAL_STRING,
            "signature_issuer": &SIGNATURE_ISSUER[..],
            "pubkey_issuer_x": &PUBKEY_ISSUER_X[..],
            "pubkey_issuer_y": &PUBKEY_ISSUER_Y[..],
        });
        let abi = get_issuer_signature_abi();
        let witness = build_witness(&input_json.to_string(), abi).unwrap();
        let vk = get_noir_verification_keccak_key(
            ISSUER_SIGNATURE_CIRCUIT_FILE.to_string(),
            Some(ISSUER_SIGNATURE_SRS_FILE.to_string()),
            disable_zk,
            low_memory_mode,
        )
        .unwrap();
        let proof = generate_noir_proof_with_keccak(
            ISSUER_SIGNATURE_CIRCUIT_FILE.to_string(),
            Some(ISSUER_SIGNATURE_SRS_FILE.to_string()),
            witness,
            disable_zk,
            vk.clone(),
            low_memory_mode,
        )
        .unwrap();
        assert!(verify_noir_proof_with_keccak(
            ISSUER_SIGNATURE_CIRCUIT_FILE.to_string(),
            proof,
            disable_zk,
            vk,
            low_memory_mode,
        ));
    }

    #[test]
    #[serial_test::serial]
    fn test_get_issuer_signature_verification_poseidon_key() {
        let vk = get_noir_verification_poseidon_key(
            ISSUER_SIGNATURE_CIRCUIT_FILE.to_string(),
            Some(ISSUER_SIGNATURE_SRS_FILE.to_string()),
            false,
        );
        assert!(vk.is_ok());
        assert!(!vk.unwrap().is_empty());
    }

    #[test]
    #[serial_test::serial]
    fn test_high_level_noir_proof_issuer_signature_poseidon() {
        let on_chain = false;
        let low_memory_mode = false;
        let input_json: serde_json::Value = json!({
            "credential_string": &CREDENTIAL_STRING,
            "signature_issuer": &SIGNATURE_ISSUER[..],
            "pubkey_issuer_x": &PUBKEY_ISSUER_X[..],
            "pubkey_issuer_y": &PUBKEY_ISSUER_Y[..],
        });
        let vk = get_noir_verification_poseidon_key(
            ISSUER_SIGNATURE_CIRCUIT_FILE.to_string(),
            Some(ISSUER_SIGNATURE_SRS_FILE.to_string()),
            false,
        )
        .unwrap();
        let proof = generate_noir_proof(
            ISSUER_SIGNATURE_CIRCUIT_FILE.to_string(),
            Some(ISSUER_SIGNATURE_SRS_FILE.to_string()),
            &input_json.to_string(),
            on_chain,
            vk.clone(),
            low_memory_mode,
            "IssuerSignature",
        )
        .unwrap();
        let is_valid = verify_noir_proof(
            ISSUER_SIGNATURE_CIRCUIT_FILE.to_string(),
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
    fn test_high_level_noir_proof_issuer_signature_keccak() {
        let on_chain = true;
        let low_memory_mode = false;
        let disable_zk = false;
        let input_json: serde_json::Value = json!({
            "credential_string": &CREDENTIAL_STRING,
            "signature_issuer": &SIGNATURE_ISSUER[..],
            "pubkey_issuer_x": &PUBKEY_ISSUER_X[..],
            "pubkey_issuer_y": &PUBKEY_ISSUER_Y[..],
        });
        let vk = get_noir_verification_keccak_key(
            ISSUER_SIGNATURE_CIRCUIT_FILE.to_string(),
            Some(ISSUER_SIGNATURE_SRS_FILE.to_string()),
            disable_zk,
            low_memory_mode,
        )
        .unwrap();
        let proof = generate_noir_proof(
            ISSUER_SIGNATURE_CIRCUIT_FILE.to_string(),
            Some(ISSUER_SIGNATURE_SRS_FILE.to_string()),
            &input_json.to_string(),
            on_chain,
            vk.clone(),
            low_memory_mode,
            "IssuerSignature",
        )
        .unwrap();
        let is_valid =
            verify_noir_proof(ISSUER_SIGNATURE_CIRCUIT_FILE.to_string(), proof, on_chain, vk, low_memory_mode)
                .unwrap();
        assert!(is_valid);
    }

    #[test]
    #[serial_test::serial]
    fn test_get_noir_verification_key_issuer_signature_poseidon() {
        let vk = get_noir_verification_key(
            ISSUER_SIGNATURE_CIRCUIT_FILE.to_string(),
            Some(ISSUER_SIGNATURE_SRS_FILE.to_string()),
            false, // off-chain, uses Poseidon
            false,
        );
        assert!(vk.is_ok());
        assert!(!vk.unwrap().is_empty());
    }

    #[test]
    #[serial_test::serial]
    fn test_get_noir_verification_key_issuer_signature_keccak() {
        let vk = get_noir_verification_key(
            ISSUER_SIGNATURE_CIRCUIT_FILE.to_string(),
            Some(ISSUER_SIGNATURE_SRS_FILE.to_string()),
            true, // on-chain, uses Keccak
            false,
        );
        assert!(vk.is_ok());
        assert!(!vk.unwrap().is_empty());
    }

    #[test]
    #[serial_test::serial]
    fn test_noir_app_macro_issuer_signature() {
        let low_memory_mode = false;
        let input_json: serde_json::Value = json!({
            "credential_string": &CREDENTIAL_STRING,
            "signature_issuer": &SIGNATURE_ISSUER[..],
            "pubkey_issuer_x": &PUBKEY_ISSUER_X[..],
            "pubkey_issuer_y": &PUBKEY_ISSUER_Y[..],
        });
        let vk_offchain = get_noir_verification_key(
            ISSUER_SIGNATURE_CIRCUIT_FILE.to_string(),
            Some(ISSUER_SIGNATURE_SRS_FILE.to_string()),
            false,
            low_memory_mode,
        )
        .unwrap();
        let vk_onchain = get_noir_verification_key(
            ISSUER_SIGNATURE_CIRCUIT_FILE.to_string(),
            Some(ISSUER_SIGNATURE_SRS_FILE.to_string()),
            true,
            low_memory_mode,
        )
        .unwrap();
        let proof_offchain = generate_noir_proof(
            ISSUER_SIGNATURE_CIRCUIT_FILE.to_string(),
            Some(ISSUER_SIGNATURE_SRS_FILE.to_string()),
            &input_json.to_string(),
            false,
            vk_offchain.clone(),
            low_memory_mode,
            "IssuerSignature",
        );
        let proof_onchain = generate_noir_proof(
            ISSUER_SIGNATURE_CIRCUIT_FILE.to_string(),
            Some(ISSUER_SIGNATURE_SRS_FILE.to_string()),
            &input_json.to_string(),
            true,
            vk_onchain.clone(),
            low_memory_mode,
            "IssuerSignature",
        );

        assert!(proof_offchain.is_ok());
        assert!(proof_onchain.is_ok());
        let proof_offchain = proof_offchain.unwrap();
        let proof_onchain = proof_onchain.unwrap();

        let verify_result_offchain = verify_noir_proof(
            ISSUER_SIGNATURE_CIRCUIT_FILE.to_string(),
            proof_offchain.clone(),
            false,
            vk_offchain,
            low_memory_mode,
        );
        let verify_result_onchain = verify_noir_proof(
            ISSUER_SIGNATURE_CIRCUIT_FILE.to_string(),
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

    #[test]
    #[serial_test::serial]
    fn test_proof_age_verification() {
        let low_memory_mode = false;
        let input_json: serde_json::Value = json!({
            "credential_string": &CREDENTIAL_STRING,
            "current_date": &CURRENT_DATE,
        });
        let abi = get_age_verification_abi();
        let witness = build_witness(&input_json.to_string(), abi).unwrap();
        let vk = get_noir_verification_poseidon_key(
            AGE_VERIFICATION_CIRCUIT_FILE.to_string(),
            Some(AGE_VERIFICATION_SRS_FILE.to_string()),
            low_memory_mode,
        )
        .unwrap();
        let proof = generate_noir_proof_with_poseidon(
            AGE_VERIFICATION_CIRCUIT_FILE.to_string(),
            Some(AGE_VERIFICATION_SRS_FILE.to_string()),
            witness,
            vk.clone(),
            low_memory_mode,
            )
            .unwrap();
        assert!(verify_noir_proof_with_poseidon(
            AGE_VERIFICATION_CIRCUIT_FILE.to_string(),
            proof,
            vk,
            low_memory_mode,
        ));
    }

    #[test]
    #[serial_test::serial]
    fn test_proof_age_verification_low_memory() {
        let low_memory_mode = true;
        let input_json: serde_json::Value = json!({
            "credential_string": &CREDENTIAL_STRING,
            "current_date": &CURRENT_DATE,
        });
        let abi = get_age_verification_abi();
        let witness = build_witness(&input_json.to_string(), abi).unwrap();
        let vk = get_noir_verification_poseidon_key(
            AGE_VERIFICATION_CIRCUIT_FILE.to_string(),
            Some(AGE_VERIFICATION_SRS_FILE.to_string()),
            low_memory_mode,
        )
        .unwrap();
        let proof = generate_noir_proof_with_poseidon(
            AGE_VERIFICATION_CIRCUIT_FILE.to_string(),
            Some(AGE_VERIFICATION_SRS_FILE.to_string()),
            witness,
            vk.clone(),
            low_memory_mode,
            )
            .unwrap();
        assert!(verify_noir_proof_with_poseidon(
            AGE_VERIFICATION_CIRCUIT_FILE.to_string(),
            proof,
            vk,
            low_memory_mode,
        ));
    }

    #[test]
    #[serial_test::serial]
    fn test_proof_age_verification_without_srs_path() {
        let low_memory_mode = false;
        let input_json: serde_json::Value = json!({
            "credential_string": &CREDENTIAL_STRING,
            "current_date": &CURRENT_DATE,
        });
        let abi = get_age_verification_abi();
        let witness = build_witness(&input_json.to_string(), abi).unwrap();
        let vk = get_noir_verification_poseidon_key(
            AGE_VERIFICATION_CIRCUIT_FILE.to_string(),
            None,
            low_memory_mode,
        )
        .unwrap();
        let proof = generate_noir_proof_with_poseidon(
            AGE_VERIFICATION_CIRCUIT_FILE.to_string(),
            None,
            witness,
            vk.clone(),
            low_memory_mode,
            )
            .unwrap();
        assert!(verify_noir_proof_with_poseidon(
            AGE_VERIFICATION_CIRCUIT_FILE.to_string(),
            proof,
            vk,
            low_memory_mode,
        ));
    }

    #[test]
    #[serial_test::serial]
    fn test_keccak_proof_age_verification() {
        let low_memory_mode = false;
        let disable_zk = false;
        let input_json: serde_json::Value = json!({
            "credential_string": &CREDENTIAL_STRING,
            "current_date": &CURRENT_DATE,
        });
        let abi = get_age_verification_abi();
        let witness = build_witness(&input_json.to_string(), abi).unwrap();
        let vk = get_noir_verification_keccak_key(
            AGE_VERIFICATION_CIRCUIT_FILE.to_string(),
            Some(AGE_VERIFICATION_SRS_FILE.to_string()),
            disable_zk,
            low_memory_mode,
        )
        .unwrap();
        let proof = generate_noir_proof_with_keccak(
            AGE_VERIFICATION_CIRCUIT_FILE.to_string(),
            Some(AGE_VERIFICATION_SRS_FILE.to_string()),
            witness,
            disable_zk,
            vk.clone(),
            low_memory_mode,
        )
        .unwrap();
        assert!(verify_noir_proof_with_keccak(
            AGE_VERIFICATION_CIRCUIT_FILE.to_string(),
            proof,
            disable_zk,
            vk,
            low_memory_mode,
        ));
    }

    #[test]
    #[serial_test::serial]
    fn test_keccak_proof_age_verification_disable_zk() {
        let low_memory_mode = false;
        let disable_zk = true;
        let input_json: serde_json::Value = json!({
            "credential_string": &CREDENTIAL_STRING,
            "current_date": &CURRENT_DATE,
        });
        let abi = get_age_verification_abi();
        let witness = build_witness(&input_json.to_string(), abi).unwrap();
        let vk = get_noir_verification_keccak_key(
            AGE_VERIFICATION_CIRCUIT_FILE.to_string(),
            Some(AGE_VERIFICATION_SRS_FILE.to_string()),
            disable_zk,
            low_memory_mode,
        )
        .unwrap();
        let proof = generate_noir_proof_with_keccak(
            AGE_VERIFICATION_CIRCUIT_FILE.to_string(),
            Some(AGE_VERIFICATION_SRS_FILE.to_string()),
            witness,
            disable_zk,
            vk.clone(),
            low_memory_mode,
        )
        .unwrap();
        assert!(verify_noir_proof_with_keccak(
            AGE_VERIFICATION_CIRCUIT_FILE.to_string(),
            proof,
            disable_zk,
            vk,
            low_memory_mode,
        ));
    }

    #[test]
    #[serial_test::serial]
    fn test_keccak_proof_age_verification_low_memory() {
        let low_memory_mode = true;
        let disable_zk = false;
        let input_json: serde_json::Value = json!({
            "credential_string": &CREDENTIAL_STRING,
            "current_date": &CURRENT_DATE,
        });
        let abi = get_age_verification_abi();
        let witness = build_witness(&input_json.to_string(), abi).unwrap();
        let vk = get_noir_verification_keccak_key(
            AGE_VERIFICATION_CIRCUIT_FILE.to_string(),
            Some(AGE_VERIFICATION_SRS_FILE.to_string()),
            disable_zk,
            low_memory_mode,
        )
        .unwrap();
        let proof = generate_noir_proof_with_keccak(
            AGE_VERIFICATION_CIRCUIT_FILE.to_string(),
            Some(AGE_VERIFICATION_SRS_FILE.to_string()),
            witness,
            disable_zk,
            vk.clone(),
            low_memory_mode,
        )
        .unwrap();
        assert!(verify_noir_proof_with_keccak(
            AGE_VERIFICATION_CIRCUIT_FILE.to_string(),
            proof,
            disable_zk,
            vk,
            low_memory_mode,
        ));
    }

    #[test]
    #[serial_test::serial]
    fn test_get_age_verification_verification_poseidon_key() {
        let vk = get_noir_verification_poseidon_key(
            AGE_VERIFICATION_CIRCUIT_FILE.to_string(),
            Some(AGE_VERIFICATION_SRS_FILE.to_string()),
            false,
        );
        assert!(vk.is_ok());
        assert!(!vk.unwrap().is_empty());
    }

    #[test]
    #[serial_test::serial]
    fn test_high_level_noir_proof_age_verification_poseidon() {
        let on_chain = false;
        let low_memory_mode = false;
        let input_json: serde_json::Value = json!({
            "credential_string": &CREDENTIAL_STRING,
            "current_date": &CURRENT_DATE,
        });
        let vk = get_noir_verification_poseidon_key(
            AGE_VERIFICATION_CIRCUIT_FILE.to_string(),
            Some(AGE_VERIFICATION_SRS_FILE.to_string()),
            false,
        )
        .unwrap();
        let proof = generate_noir_proof(
            AGE_VERIFICATION_CIRCUIT_FILE.to_string(),
            Some(AGE_VERIFICATION_SRS_FILE.to_string()),
            &input_json.to_string(),
            on_chain,
            vk.clone(),
            low_memory_mode,
            "AgeVerification",
        )
        .unwrap();
        let is_valid = verify_noir_proof(
            AGE_VERIFICATION_CIRCUIT_FILE.to_string(),
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
    fn test_high_level_noir_proof_age_verification_keccak() {
        let on_chain = true;
        let low_memory_mode = false;
        let disable_zk = false;
        let input_json: serde_json::Value = json!({
            "credential_string": &CREDENTIAL_STRING,
            "current_date": &CURRENT_DATE,
        });
        let vk = get_noir_verification_keccak_key(
            AGE_VERIFICATION_CIRCUIT_FILE.to_string(),
            Some(AGE_VERIFICATION_SRS_FILE.to_string()),
            disable_zk,
            low_memory_mode,
        )
        .unwrap();
        let proof = generate_noir_proof(
            AGE_VERIFICATION_CIRCUIT_FILE.to_string(),
            Some(AGE_VERIFICATION_SRS_FILE.to_string()),
            &input_json.to_string(),
            on_chain,
            vk.clone(),
            low_memory_mode,
            "AgeVerification",
        )
        .unwrap();
        let is_valid =
            verify_noir_proof(AGE_VERIFICATION_CIRCUIT_FILE.to_string(), proof, on_chain, vk, low_memory_mode)
                .unwrap();
        assert!(is_valid);
    }

    #[test]
    #[serial_test::serial]
    fn test_get_noir_verification_key_age_verification_poseidon() {
        let vk = get_noir_verification_key(
            AGE_VERIFICATION_CIRCUIT_FILE.to_string(),
            Some(AGE_VERIFICATION_SRS_FILE.to_string()),
            false, // off-chain, uses Poseidon
            false,
        );
        assert!(vk.is_ok());
        assert!(!vk.unwrap().is_empty());
    }

    #[test]
    #[serial_test::serial]
    fn test_get_noir_verification_key_age_verification_keccak() {
        let vk = get_noir_verification_key(
            AGE_VERIFICATION_CIRCUIT_FILE.to_string(),
            Some(AGE_VERIFICATION_SRS_FILE.to_string()),
            true, // on-chain, uses Keccak
            false,
        );
        assert!(vk.is_ok());
        assert!(!vk.unwrap().is_empty());
    }

    #[test]
    #[serial_test::serial]
    fn test_noir_app_macro_age_verification() {
        let low_memory_mode = false;
        let input_json: serde_json::Value = json!({
            "credential_string": &CREDENTIAL_STRING,
            "current_date": &CURRENT_DATE,
        });
        let vk_offchain = get_noir_verification_key(
            AGE_VERIFICATION_CIRCUIT_FILE.to_string(),
            Some(AGE_VERIFICATION_SRS_FILE.to_string()),
            false,
            low_memory_mode,
        )
        .unwrap();
        let vk_onchain = get_noir_verification_key(
            AGE_VERIFICATION_CIRCUIT_FILE.to_string(),
            Some(AGE_VERIFICATION_SRS_FILE.to_string()),
            true,
            low_memory_mode,
        )
        .unwrap();
        let proof_offchain = generate_noir_proof(
            AGE_VERIFICATION_CIRCUIT_FILE.to_string(),
            Some(AGE_VERIFICATION_SRS_FILE.to_string()),
            &input_json.to_string(),
            false,
            vk_offchain.clone(),
            low_memory_mode,
            "AgeVerification",
        );
        let proof_onchain = generate_noir_proof(
            AGE_VERIFICATION_CIRCUIT_FILE.to_string(),
            Some(AGE_VERIFICATION_SRS_FILE.to_string()),
            &input_json.to_string(),
            true,
            vk_onchain.clone(),
            low_memory_mode,
            "AgeVerification",
        );

        assert!(proof_offchain.is_ok());
        assert!(proof_onchain.is_ok());
        let proof_offchain = proof_offchain.unwrap();
        let proof_onchain = proof_onchain.unwrap();

        let verify_result_offchain = verify_noir_proof(
            AGE_VERIFICATION_CIRCUIT_FILE.to_string(),
            proof_offchain.clone(),
            false,
            vk_offchain,
            low_memory_mode,
        );
        let verify_result_onchain = verify_noir_proof(
            AGE_VERIFICATION_CIRCUIT_FILE.to_string(),
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

    #[test]
    #[serial_test::serial]
    fn test_proof_non_revocation() {
        let low_memory_mode = false;
        let input_json: serde_json::Value = json!({
            "credential_string": &CREDENTIAL_STRING,
            "current_date": &CURRENT_DATE,
            "revocation_list": &REVOCATION_LIST[..],
            "pubkey_issuer_x": &PUBKEY_ISSUER_X[..],
            "pubkey_issuer_y": &PUBKEY_ISSUER_Y[..],
        });
        let abi = get_non_revocation_abi();
        let witness = build_witness(&input_json.to_string(), abi).unwrap();
        let vk = get_noir_verification_poseidon_key(
            NON_REVOCATION_CIRCUIT_FILE.to_string(),
            Some(NON_REVOCATION_SRS_FILE.to_string()),
            low_memory_mode,
        )
        .unwrap();
        let proof = generate_noir_proof_with_poseidon(
            NON_REVOCATION_CIRCUIT_FILE.to_string(),
            Some(NON_REVOCATION_SRS_FILE.to_string()),
            witness,
            vk.clone(),
            low_memory_mode,
            )
            .unwrap();
        assert!(verify_noir_proof_with_poseidon(
            NON_REVOCATION_CIRCUIT_FILE.to_string(),
            proof,
            vk,
            low_memory_mode,
        ));
    }

    #[test]
    #[serial_test::serial]
    fn test_proof_non_revocation_low_memory() {
        let low_memory_mode = true;
        let input_json: serde_json::Value = json!({
            "credential_string": &CREDENTIAL_STRING,
            "current_date": &CURRENT_DATE,
            "revocation_list": &REVOCATION_LIST[..],
            "pubkey_issuer_x": &PUBKEY_ISSUER_X[..],
            "pubkey_issuer_y": &PUBKEY_ISSUER_Y[..],
        });
        let abi = get_non_revocation_abi();
        let witness = build_witness(&input_json.to_string(), abi).unwrap();
        let vk = get_noir_verification_poseidon_key(
            NON_REVOCATION_CIRCUIT_FILE.to_string(),
            Some(NON_REVOCATION_SRS_FILE.to_string()),
            low_memory_mode,
        )
        .unwrap();
        let proof = generate_noir_proof_with_poseidon(
            NON_REVOCATION_CIRCUIT_FILE.to_string(),
            Some(NON_REVOCATION_SRS_FILE.to_string()),
            witness,
            vk.clone(),
            low_memory_mode,
            )
            .unwrap();
        assert!(verify_noir_proof_with_poseidon(
            NON_REVOCATION_CIRCUIT_FILE.to_string(),
            proof,
            vk,
            low_memory_mode,
        ));
    }

    #[test]
    #[serial_test::serial]
    fn test_proof_non_revocation_without_srs_path() {
        let low_memory_mode = false;
        let input_json: serde_json::Value = json!({
            "credential_string": &CREDENTIAL_STRING,
            "current_date": &CURRENT_DATE,
            "revocation_list": &REVOCATION_LIST[..],
            "pubkey_issuer_x": &PUBKEY_ISSUER_X[..],
            "pubkey_issuer_y": &PUBKEY_ISSUER_Y[..],
        });
        let abi = get_non_revocation_abi();
        let witness = build_witness(&input_json.to_string(), abi).unwrap();
        let vk = get_noir_verification_poseidon_key(
            NON_REVOCATION_CIRCUIT_FILE.to_string(),
            None,
            low_memory_mode,
        )
        .unwrap();
        let proof = generate_noir_proof_with_poseidon(
            NON_REVOCATION_CIRCUIT_FILE.to_string(),
            None,
            witness,
            vk.clone(),
            low_memory_mode,
            )
            .unwrap();
        assert!(verify_noir_proof_with_poseidon(
            NON_REVOCATION_CIRCUIT_FILE.to_string(),
            proof,
            vk,
            low_memory_mode,
        ));
    }

    #[test]
    #[serial_test::serial]
    fn test_keccak_proof_non_revocation() {
        let low_memory_mode = false;
        let disable_zk = false;
        let input_json: serde_json::Value = json!({
            "credential_string": &CREDENTIAL_STRING,
            "current_date": &CURRENT_DATE,
            "revocation_list": &REVOCATION_LIST[..],
            "pubkey_issuer_x": &PUBKEY_ISSUER_X[..],
            "pubkey_issuer_y": &PUBKEY_ISSUER_Y[..],
        });
        let abi = get_non_revocation_abi();
        let witness = build_witness(&input_json.to_string(), abi).unwrap();
        let vk = get_noir_verification_keccak_key(
            NON_REVOCATION_CIRCUIT_FILE.to_string(),
            Some(NON_REVOCATION_SRS_FILE.to_string()),
            disable_zk,
            low_memory_mode,
        )
        .unwrap();
        let proof = generate_noir_proof_with_keccak(
            NON_REVOCATION_CIRCUIT_FILE.to_string(),
            Some(NON_REVOCATION_SRS_FILE.to_string()),
            witness,
            disable_zk,
            vk.clone(),
            low_memory_mode,
        )
        .unwrap();
        assert!(verify_noir_proof_with_keccak(
            NON_REVOCATION_CIRCUIT_FILE.to_string(),
            proof,
            disable_zk,
            vk,
            low_memory_mode,
        ));
    }

    #[test]
    #[serial_test::serial]
    fn test_keccak_proof_non_revocation_disable_zk() {
        let low_memory_mode = false;
        let disable_zk = true;
        let input_json: serde_json::Value = json!({
            "credential_string": &CREDENTIAL_STRING,
            "current_date": &CURRENT_DATE,
            "revocation_list": &REVOCATION_LIST[..],
            "pubkey_issuer_x": &PUBKEY_ISSUER_X[..],
            "pubkey_issuer_y": &PUBKEY_ISSUER_Y[..],
        });
        let abi = get_non_revocation_abi();
        let witness = build_witness(&input_json.to_string(), abi).unwrap();
        let vk = get_noir_verification_keccak_key(
            NON_REVOCATION_CIRCUIT_FILE.to_string(),
            Some(NON_REVOCATION_SRS_FILE.to_string()),
            disable_zk,
            low_memory_mode,
        )
        .unwrap();
        let proof = generate_noir_proof_with_keccak(
            NON_REVOCATION_CIRCUIT_FILE.to_string(),
            Some(NON_REVOCATION_SRS_FILE.to_string()),
            witness,
            disable_zk,
            vk.clone(),
            low_memory_mode,
        )
        .unwrap();
        assert!(verify_noir_proof_with_keccak(
            NON_REVOCATION_CIRCUIT_FILE.to_string(),
            proof,
            disable_zk,
            vk,
            low_memory_mode,
        ));
    }

    #[test]
    #[serial_test::serial]
    fn test_keccak_proof_non_revocation_low_memory() {
        let low_memory_mode = true;
        let disable_zk = false;
        let input_json: serde_json::Value = json!({
            "credential_string": &CREDENTIAL_STRING,
            "current_date": &CURRENT_DATE,
            "revocation_list": &REVOCATION_LIST[..],
            "pubkey_issuer_x": &PUBKEY_ISSUER_X[..],
            "pubkey_issuer_y": &PUBKEY_ISSUER_Y[..],
        });
        let abi = get_non_revocation_abi();
        let witness = build_witness(&input_json.to_string(), abi).unwrap();
        let vk = get_noir_verification_keccak_key(
            NON_REVOCATION_CIRCUIT_FILE.to_string(),
            Some(NON_REVOCATION_SRS_FILE.to_string()),
            disable_zk,
            low_memory_mode,
        )
        .unwrap();
        let proof = generate_noir_proof_with_keccak(
            NON_REVOCATION_CIRCUIT_FILE.to_string(),
            Some(NON_REVOCATION_SRS_FILE.to_string()),
            witness,
            disable_zk,
            vk.clone(),
            low_memory_mode,
        )
        .unwrap();
        assert!(verify_noir_proof_with_keccak(
            NON_REVOCATION_CIRCUIT_FILE.to_string(),
            proof,
            disable_zk,
            vk,
            low_memory_mode,
        ));
    }

    #[test]
    #[serial_test::serial]
    fn test_get_non_revocation_verification_poseidon_key() {
        let vk = get_noir_verification_poseidon_key(
            NON_REVOCATION_CIRCUIT_FILE.to_string(),
            Some(NON_REVOCATION_SRS_FILE.to_string()),
            false,
        );
        assert!(vk.is_ok());
        assert!(!vk.unwrap().is_empty());
    }

    #[test]
    #[serial_test::serial]
    fn test_high_level_noir_proof_non_revocation_poseidon() {
        let on_chain = false;
        let low_memory_mode = false;
        let input_json: serde_json::Value = json!({
            "credential_string": &CREDENTIAL_STRING,
            "current_date": &CURRENT_DATE,
            "revocation_list": &REVOCATION_LIST[..],
            "pubkey_issuer_x": &PUBKEY_ISSUER_X[..],
            "pubkey_issuer_y": &PUBKEY_ISSUER_Y[..],
        });
        let vk = get_noir_verification_poseidon_key(
            NON_REVOCATION_CIRCUIT_FILE.to_string(),
            Some(NON_REVOCATION_SRS_FILE.to_string()),
            false,
        )
        .unwrap();
        let proof = generate_noir_proof(
            NON_REVOCATION_CIRCUIT_FILE.to_string(),
            Some(NON_REVOCATION_SRS_FILE.to_string()),
            &input_json.to_string(),
            on_chain,
            vk.clone(),
            low_memory_mode,
            "NonRevocation",
        )
        .unwrap();
        let is_valid = verify_noir_proof(
            NON_REVOCATION_CIRCUIT_FILE.to_string(),
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
    fn test_high_level_noir_proof_non_revocation_keccak() {
        let on_chain = true;
        let low_memory_mode = false;
        let disable_zk = false;
        let input_json: serde_json::Value = json!({
            "credential_string": &CREDENTIAL_STRING,
            "current_date": &CURRENT_DATE,
            "revocation_list": &REVOCATION_LIST[..],
            "pubkey_issuer_x": &PUBKEY_ISSUER_X[..],
            "pubkey_issuer_y": &PUBKEY_ISSUER_Y[..],
        });
        let vk = get_noir_verification_keccak_key(
            NON_REVOCATION_CIRCUIT_FILE.to_string(),
            Some(NON_REVOCATION_SRS_FILE.to_string()),
            disable_zk,
            low_memory_mode,
        )
        .unwrap();
        let proof = generate_noir_proof(
            NON_REVOCATION_CIRCUIT_FILE.to_string(),
            Some(NON_REVOCATION_SRS_FILE.to_string()),
            &input_json.to_string(),
            on_chain,
            vk.clone(),
            low_memory_mode,
            "NonRevocation",
        )
        .unwrap();
        let is_valid =
            verify_noir_proof(NON_REVOCATION_CIRCUIT_FILE.to_string(), proof, on_chain, vk, low_memory_mode)
                .unwrap();
        assert!(is_valid);
    }

    #[test]
    #[serial_test::serial]
    fn test_get_noir_verification_key_non_revocation_poseidon() {
        let vk = get_noir_verification_key(
            NON_REVOCATION_CIRCUIT_FILE.to_string(),
            Some(NON_REVOCATION_SRS_FILE.to_string()),
            false, // off-chain, uses Poseidon
            false,
        );
        assert!(vk.is_ok());
        assert!(!vk.unwrap().is_empty());
    }

    #[test]
    #[serial_test::serial]
    fn test_get_noir_verification_key_non_revocation_keccak() {
        let vk = get_noir_verification_key(
            NON_REVOCATION_CIRCUIT_FILE.to_string(),
            Some(NON_REVOCATION_SRS_FILE.to_string()),
            true, // on-chain, uses Keccak
            false,
        );
        assert!(vk.is_ok());
        assert!(!vk.unwrap().is_empty());
    }

    #[test]
    #[serial_test::serial]
    fn test_noir_app_macro_non_revocation() {
        let low_memory_mode = false;
        let input_json: serde_json::Value = json!({
            "credential_string": &CREDENTIAL_STRING,
            "current_date": &CURRENT_DATE,
            "revocation_list": &REVOCATION_LIST[..],
            "pubkey_issuer_x": &PUBKEY_ISSUER_X[..],
            "pubkey_issuer_y": &PUBKEY_ISSUER_Y[..],
        });
        let vk_offchain = get_noir_verification_key(
            NON_REVOCATION_CIRCUIT_FILE.to_string(),
            Some(NON_REVOCATION_SRS_FILE.to_string()),
            false,
            low_memory_mode,
        )
        .unwrap();
        let vk_onchain = get_noir_verification_key(
            NON_REVOCATION_CIRCUIT_FILE.to_string(),
            Some(NON_REVOCATION_SRS_FILE.to_string()),
            true,
            low_memory_mode,
        )
        .unwrap();
        let proof_offchain = generate_noir_proof(
            NON_REVOCATION_CIRCUIT_FILE.to_string(),
            Some(NON_REVOCATION_SRS_FILE.to_string()),
            &input_json.to_string(),
            false,
            vk_offchain.clone(),
            low_memory_mode,
            "NonRevocation",
        );
        let proof_onchain = generate_noir_proof(
            NON_REVOCATION_CIRCUIT_FILE.to_string(),
            Some(NON_REVOCATION_SRS_FILE.to_string()),
            &input_json.to_string(),
            true,
            vk_onchain.clone(),
            low_memory_mode,
            "NonRevocation",
        );

        assert!(proof_offchain.is_ok());
        assert!(proof_onchain.is_ok());
        let proof_offchain = proof_offchain.unwrap();
        let proof_onchain = proof_onchain.unwrap();

        let verify_result_offchain = verify_noir_proof(
            NON_REVOCATION_CIRCUIT_FILE.to_string(),
            proof_offchain.clone(),
            false,
            vk_offchain,
            low_memory_mode,
        );
        let verify_result_onchain = verify_noir_proof(
            NON_REVOCATION_CIRCUIT_FILE.to_string(),
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

    #[test]
    #[serial_test::serial]
    fn test_proof_full_proof() {
        let low_memory_mode = false;
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
        let abi = get_full_proof_abi();
        let witness = build_witness(&input_json.to_string(), abi).unwrap();
        let vk = get_noir_verification_poseidon_key(
            FULL_PROOF_CIRCUIT_FILE.to_string(),
            Some(FULL_PROOF_SRS_FILE.to_string()),
            low_memory_mode,
        )
        .unwrap();
        let proof = generate_noir_proof_with_poseidon(
            FULL_PROOF_CIRCUIT_FILE.to_string(),
            Some(FULL_PROOF_SRS_FILE.to_string()),
            witness,
            vk.clone(),
            low_memory_mode,
            )
            .unwrap();
        assert!(verify_noir_proof_with_poseidon(
            FULL_PROOF_CIRCUIT_FILE.to_string(),
            proof,
            vk,
            low_memory_mode,
        ));
    }

    #[test]
    #[serial_test::serial]
    fn test_proof_full_proof_low_memory() {
        let low_memory_mode = true;
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
        let abi = get_full_proof_abi();
        let witness = build_witness(&input_json.to_string(), abi).unwrap();
        let vk = get_noir_verification_poseidon_key(
            FULL_PROOF_CIRCUIT_FILE.to_string(),
            Some(FULL_PROOF_SRS_FILE.to_string()),
            low_memory_mode,
        )
        .unwrap();
        let proof = generate_noir_proof_with_poseidon(
            FULL_PROOF_CIRCUIT_FILE.to_string(),
            Some(FULL_PROOF_SRS_FILE.to_string()),
            witness,
            vk.clone(),
            low_memory_mode,
            )
            .unwrap();
        assert!(verify_noir_proof_with_poseidon(
            FULL_PROOF_CIRCUIT_FILE.to_string(),
            proof,
            vk,
            low_memory_mode,
        ));
    }

    #[test]
    #[serial_test::serial]
    fn test_proof_full_proof_without_srs_path() {
        let low_memory_mode = false;
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
        let abi = get_full_proof_abi();
        let witness = build_witness(&input_json.to_string(), abi).unwrap();
        let vk = get_noir_verification_poseidon_key(
            FULL_PROOF_CIRCUIT_FILE.to_string(),
            None,
            low_memory_mode,
        )
        .unwrap();
        let proof = generate_noir_proof_with_poseidon(
            FULL_PROOF_CIRCUIT_FILE.to_string(),
            None,
            witness,
            vk.clone(),
            low_memory_mode,
            )
            .unwrap();
        assert!(verify_noir_proof_with_poseidon(
            FULL_PROOF_CIRCUIT_FILE.to_string(),
            proof,
            vk,
            low_memory_mode,
        ));
    }

    #[test]
    #[serial_test::serial]
    fn test_keccak_proof_full_proof() {
        let low_memory_mode = false;
        let disable_zk = false;
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
        let abi = get_full_proof_abi();
        let witness = build_witness(&input_json.to_string(), abi).unwrap();
        let vk = get_noir_verification_keccak_key(
            FULL_PROOF_CIRCUIT_FILE.to_string(),
            Some(FULL_PROOF_SRS_FILE.to_string()),
            disable_zk,
            low_memory_mode,
        )
        .unwrap();
        let proof = generate_noir_proof_with_keccak(
            FULL_PROOF_CIRCUIT_FILE.to_string(),
            Some(FULL_PROOF_SRS_FILE.to_string()),
            witness,
            disable_zk,
            vk.clone(),
            low_memory_mode,
        )
        .unwrap();
        assert!(verify_noir_proof_with_keccak(
            FULL_PROOF_CIRCUIT_FILE.to_string(),
            proof,
            disable_zk,
            vk,
            low_memory_mode,
        ));
    }

    #[test]
    #[serial_test::serial]
    fn test_keccak_proof_full_proof_disable_zk() {
        let low_memory_mode = false;
        let disable_zk = true;
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
        let abi = get_full_proof_abi();
        let witness = build_witness(&input_json.to_string(), abi).unwrap();
        let vk = get_noir_verification_keccak_key(
            FULL_PROOF_CIRCUIT_FILE.to_string(),
            Some(FULL_PROOF_SRS_FILE.to_string()),
            disable_zk,
            low_memory_mode,
        )
        .unwrap();
        let proof = generate_noir_proof_with_keccak(
            FULL_PROOF_CIRCUIT_FILE.to_string(),
            Some(FULL_PROOF_SRS_FILE.to_string()),
            witness,
            disable_zk,
            vk.clone(),
            low_memory_mode,
        )
        .unwrap();
        assert!(verify_noir_proof_with_keccak(
            FULL_PROOF_CIRCUIT_FILE.to_string(),
            proof,
            disable_zk,
            vk,
            low_memory_mode,
        ));
    }

    #[test]
    #[serial_test::serial]
    fn test_keccak_proof_full_proof_low_memory() {
        let low_memory_mode = true;
        let disable_zk = false;
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
        let abi = get_full_proof_abi();
        let witness = build_witness(&input_json.to_string(), abi).unwrap();
        let vk = get_noir_verification_keccak_key(
            FULL_PROOF_CIRCUIT_FILE.to_string(),
            Some(FULL_PROOF_SRS_FILE.to_string()),
            disable_zk,
            low_memory_mode,
        )
        .unwrap();
        let proof = generate_noir_proof_with_keccak(
            FULL_PROOF_CIRCUIT_FILE.to_string(),
            Some(FULL_PROOF_SRS_FILE.to_string()),
            witness,
            disable_zk,
            vk.clone(),
            low_memory_mode,
        )
        .unwrap();
        assert!(verify_noir_proof_with_keccak(
            FULL_PROOF_CIRCUIT_FILE.to_string(),
            proof,
            disable_zk,
            vk,
            low_memory_mode,
        ));
    }

    #[test]
    #[serial_test::serial]
    fn test_get_full_proof_verification_poseidon_key() {
        let vk = get_noir_verification_poseidon_key(
            FULL_PROOF_CIRCUIT_FILE.to_string(),
            Some(FULL_PROOF_SRS_FILE.to_string()),
            false,
        );
        assert!(vk.is_ok());
        assert!(!vk.unwrap().is_empty());
    }

    #[test]
    #[serial_test::serial]
    fn test_high_level_noir_proof_full_proof_poseidon() {
        let on_chain = false;
        let low_memory_mode = false;
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
        let vk = get_noir_verification_poseidon_key(
            FULL_PROOF_CIRCUIT_FILE.to_string(),
            Some(FULL_PROOF_SRS_FILE.to_string()),
            false,
        )
        .unwrap();
        let proof = generate_noir_proof(
            FULL_PROOF_CIRCUIT_FILE.to_string(),
            Some(FULL_PROOF_SRS_FILE.to_string()),
            &input_json.to_string(),
            on_chain,
            vk.clone(),
            low_memory_mode,
            "FullProof",
        )
        .unwrap();
        let is_valid = verify_noir_proof(
            FULL_PROOF_CIRCUIT_FILE.to_string(),
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
    fn test_high_level_noir_proof_full_proof_keccak() {
        let on_chain = true;
        let low_memory_mode = false;
        let disable_zk = false;
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
        let vk = get_noir_verification_keccak_key(
            FULL_PROOF_CIRCUIT_FILE.to_string(),
            Some(FULL_PROOF_SRS_FILE.to_string()),
            disable_zk,
            low_memory_mode,
        )
        .unwrap();
        let proof = generate_noir_proof(
            FULL_PROOF_CIRCUIT_FILE.to_string(),
            Some(FULL_PROOF_SRS_FILE.to_string()),
            &input_json.to_string(),
            on_chain,
            vk.clone(),
            low_memory_mode,
            "FullProof",
        )
        .unwrap();
        let is_valid =
            verify_noir_proof(FULL_PROOF_CIRCUIT_FILE.to_string(), proof, on_chain, vk, low_memory_mode)
                .unwrap();
        assert!(is_valid);
    }

    #[test]
    #[serial_test::serial]
    fn test_get_noir_verification_key_full_proof_poseidon() {
        let vk = get_noir_verification_key(
            FULL_PROOF_CIRCUIT_FILE.to_string(),
            Some(FULL_PROOF_SRS_FILE.to_string()),
            false, // off-chain, uses Poseidon
            false,
        );
        assert!(vk.is_ok());
        assert!(!vk.unwrap().is_empty());
    }

    #[test]
    #[serial_test::serial]
    fn test_get_noir_verification_key_full_proof_keccak() {
        let vk = get_noir_verification_key(
            FULL_PROOF_CIRCUIT_FILE.to_string(),
            Some(FULL_PROOF_SRS_FILE.to_string()),
            true, // on-chain, uses Keccak
            false,
        );
        assert!(vk.is_ok());
        assert!(!vk.unwrap().is_empty());
    }

    #[test]
    #[serial_test::serial]
    fn test_noir_app_macro_full_proof() {
        let low_memory_mode = false;
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
        let vk_offchain = get_noir_verification_key(
            FULL_PROOF_CIRCUIT_FILE.to_string(),
            Some(FULL_PROOF_SRS_FILE.to_string()),
            false,
            low_memory_mode,
        )
        .unwrap();
        let vk_onchain = get_noir_verification_key(
            FULL_PROOF_CIRCUIT_FILE.to_string(),
            Some(FULL_PROOF_SRS_FILE.to_string()),
            true,
            low_memory_mode,
        )
        .unwrap();
        let proof_offchain = generate_noir_proof(
            FULL_PROOF_CIRCUIT_FILE.to_string(),
            Some(FULL_PROOF_SRS_FILE.to_string()),
            &input_json.to_string(),
            false,
            vk_offchain.clone(),
            low_memory_mode,
            "FullProof",
        );
        let proof_onchain = generate_noir_proof(
            FULL_PROOF_CIRCUIT_FILE.to_string(),
            Some(FULL_PROOF_SRS_FILE.to_string()),
            &input_json.to_string(),
            true,
            vk_onchain.clone(),
            low_memory_mode,
            "FullProof",
        );

        assert!(proof_offchain.is_ok());
        assert!(proof_onchain.is_ok());
        let proof_offchain = proof_offchain.unwrap();
        let proof_onchain = proof_onchain.unwrap();

        let verify_result_offchain = verify_noir_proof(
            FULL_PROOF_CIRCUIT_FILE.to_string(),
            proof_offchain.clone(),
            false,
            vk_offchain,
            low_memory_mode,
        );
        let verify_result_onchain = verify_noir_proof(
            FULL_PROOF_CIRCUIT_FILE.to_string(),
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

    #[test]
    #[serial_test::serial]
    fn test_proof_swiyu_jwt() {
        let low_memory_mode = false;
        let abi = get_swiyu_jwt_abi();
        let input_json: serde_json::Value = serde_json::from_str(
            &std::fs::read_to_string(concat!(TEST_VECTORS!(), "Prover.json"))
                .expect("failed to read prover"),
        )
        .expect("failed to parse prover");
        let witness = build_witness(&input_json.to_string(), abi).unwrap();
        let vk = get_noir_verification_poseidon_key(
            SWIYU_JWT_CIRCUIT_FILE.to_string(),
            Some(SWIYU_JWT_SRS_FILE.to_string()),
            low_memory_mode,
        )
        .unwrap();
        let proof = generate_noir_proof_with_poseidon(
            SWIYU_JWT_CIRCUIT_FILE.to_string(),
            Some(SWIYU_JWT_SRS_FILE.to_string()),
            witness,
            vk.clone(),
            low_memory_mode,
            )
            .unwrap();
        assert!(verify_noir_proof_with_poseidon(
            SWIYU_JWT_CIRCUIT_FILE.to_string(),
            proof,
            vk,
            low_memory_mode,
        ));
    }

    #[test]
    #[serial_test::serial]
    fn test_proof_swiyu_jwt_low_memory() {
        let low_memory_mode = true;
        let abi = get_swiyu_jwt_abi();
        let input_json: serde_json::Value = serde_json::from_str(
            &std::fs::read_to_string(concat!(TEST_VECTORS!(), "Prover.json"))
                .expect("failed to read prover"),
        )
        .expect("failed to parse prover");
        let witness = build_witness(&input_json.to_string(), abi).unwrap();
        let vk = get_noir_verification_poseidon_key(
            SWIYU_JWT_CIRCUIT_FILE.to_string(),
            Some(SWIYU_JWT_SRS_FILE.to_string()),
            low_memory_mode,
        )
        .unwrap();
        let proof = generate_noir_proof_with_poseidon(
            SWIYU_JWT_CIRCUIT_FILE.to_string(),
            Some(SWIYU_JWT_SRS_FILE.to_string()),
            witness,
            vk.clone(),
            low_memory_mode,
            )
            .unwrap();
        assert!(verify_noir_proof_with_poseidon(
            SWIYU_JWT_CIRCUIT_FILE.to_string(),
            proof,
            vk,
            low_memory_mode,
        ));
    }

    #[test]
    #[serial_test::serial]
    fn test_proof_swiyu_jwt_without_srs_path() {
        let low_memory_mode = false;
        let abi = get_swiyu_jwt_abi();
        let input_json: serde_json::Value = serde_json::from_str(
            &std::fs::read_to_string(concat!(TEST_VECTORS!(), "Prover.json"))
                .expect("failed to read prover"),
        )
        .expect("failed to parse prover");
        let witness = build_witness(&input_json.to_string(), abi).unwrap();
        let vk = get_noir_verification_poseidon_key(
            SWIYU_JWT_CIRCUIT_FILE.to_string(),
            None,
            low_memory_mode,
        )
        .unwrap();
        let proof = generate_noir_proof_with_poseidon(
            SWIYU_JWT_CIRCUIT_FILE.to_string(),
            None,
            witness,
            vk.clone(),
            low_memory_mode,
            )
            .unwrap();
        assert!(verify_noir_proof_with_poseidon(
            SWIYU_JWT_CIRCUIT_FILE.to_string(),
            proof,
            vk,
            low_memory_mode,
        ));
    }

    #[test]
    #[serial_test::serial]
    fn test_keccak_proof_swiyu_jwt() {
        let low_memory_mode = false;
        let disable_zk = false;
        let abi = get_swiyu_jwt_abi();
        let input_json: serde_json::Value = serde_json::from_str(
            &std::fs::read_to_string(concat!(TEST_VECTORS!(), "Prover.json"))
                .expect("failed to read prover"),
        )
        .expect("failed to parse prover");
        let witness = build_witness(&input_json.to_string(), abi).unwrap();
        let vk = get_noir_verification_keccak_key(
            SWIYU_JWT_CIRCUIT_FILE.to_string(),
            Some(SWIYU_JWT_SRS_FILE.to_string()),
            disable_zk,
            low_memory_mode,
        )
        .unwrap();
        let proof = generate_noir_proof_with_keccak(
            SWIYU_JWT_CIRCUIT_FILE.to_string(),
            Some(SWIYU_JWT_SRS_FILE.to_string()),
            witness,
            disable_zk,
            vk.clone(),
            low_memory_mode,
        )
        .unwrap();
        assert!(verify_noir_proof_with_keccak(
            SWIYU_JWT_CIRCUIT_FILE.to_string(),
            proof,
            disable_zk,
            vk,
            low_memory_mode,
        ));
    }

    #[test]
    #[serial_test::serial]
    fn test_keccak_proof_swiyu_jwt_disable_zk() {
        let low_memory_mode = false;
        let disable_zk = true;
        let abi = get_swiyu_jwt_abi();
        let input_json: serde_json::Value = serde_json::from_str(
            &std::fs::read_to_string(concat!(TEST_VECTORS!(), "Prover.json"))
                .expect("failed to read prover"),
        )
        .expect("failed to parse prover");
        let witness = build_witness(&input_json.to_string(), abi).unwrap();
        let vk = get_noir_verification_keccak_key(
            SWIYU_JWT_CIRCUIT_FILE.to_string(),
            Some(SWIYU_JWT_SRS_FILE.to_string()),
            disable_zk,
            low_memory_mode,
        )
        .unwrap();
        let proof = generate_noir_proof_with_keccak(
            SWIYU_JWT_CIRCUIT_FILE.to_string(),
            Some(SWIYU_JWT_SRS_FILE.to_string()),
            witness,
            disable_zk,
            vk.clone(),
            low_memory_mode,
        )
        .unwrap();
        assert!(verify_noir_proof_with_keccak(
            SWIYU_JWT_CIRCUIT_FILE.to_string(),
            proof,
            disable_zk,
            vk,
            low_memory_mode,
        ));
    }

    #[test]
    #[serial_test::serial]
    fn test_keccak_proof_swiyu_jwt_low_memory() {
        let low_memory_mode = true;
        let disable_zk = false;
        let abi = get_swiyu_jwt_abi();
        let input_json: serde_json::Value = serde_json::from_str(
            &std::fs::read_to_string(concat!(TEST_VECTORS!(), "Prover.json"))
                .expect("failed to read prover"),
        )
        .expect("failed to parse prover");
        let witness = build_witness(&input_json.to_string(), abi).unwrap();
        let vk = get_noir_verification_keccak_key(
            SWIYU_JWT_CIRCUIT_FILE.to_string(),
            Some(SWIYU_JWT_SRS_FILE.to_string()),
            disable_zk,
            low_memory_mode,
        )
        .unwrap();
        let proof = generate_noir_proof_with_keccak(
            SWIYU_JWT_CIRCUIT_FILE.to_string(),
            Some(SWIYU_JWT_SRS_FILE.to_string()),
            witness,
            disable_zk,
            vk.clone(),
            low_memory_mode,
        )
        .unwrap();
        assert!(verify_noir_proof_with_keccak(
            SWIYU_JWT_CIRCUIT_FILE.to_string(),
            proof,
            disable_zk,
            vk,
            low_memory_mode,
        ));
    }

    #[test]
    #[serial_test::serial]
    fn test_get_swiyu_jwt_verification_poseidon_key() {
        let vk = get_noir_verification_poseidon_key(
            SWIYU_JWT_CIRCUIT_FILE.to_string(),
            Some(SWIYU_JWT_SRS_FILE.to_string()),
            false,
        );
        assert!(vk.is_ok());
        assert!(!vk.unwrap().is_empty());
    }

    #[test]
    #[serial_test::serial]
    fn test_high_level_noir_proof_swiyu_jwt_poseidon() {
        let on_chain = false;
        let low_memory_mode = false;
        let input_json: serde_json::Value = serde_json::from_str(
            &std::fs::read_to_string(concat!(TEST_VECTORS!(), "Prover.json"))
                .expect("failed to read prover"),
        )
        .expect("failed to parse prover");
        let vk = get_noir_verification_poseidon_key(
            SWIYU_JWT_CIRCUIT_FILE.to_string(),
            Some(SWIYU_JWT_SRS_FILE.to_string()),
            false,
        )
        .unwrap();
        let proof = generate_noir_proof(
            SWIYU_JWT_CIRCUIT_FILE.to_string(),
            Some(SWIYU_JWT_SRS_FILE.to_string()),
            &input_json.to_string(),
            on_chain,
            vk.clone(),
            low_memory_mode,
            "SwiyuJwt",
        )
        .unwrap();
        let is_valid = verify_noir_proof(
            SWIYU_JWT_CIRCUIT_FILE.to_string(),
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
    fn test_high_level_noir_proof_swiyu_jwt_keccak() {
        let on_chain = true;
        let low_memory_mode = false;
        let disable_zk = false;
        let input_json: serde_json::Value = serde_json::from_str(
            &std::fs::read_to_string(concat!(TEST_VECTORS!(), "Prover.json"))
                .expect("failed to read prover"),
        )
        .expect("failed to parse prover");
        let vk = get_noir_verification_keccak_key(
            SWIYU_JWT_CIRCUIT_FILE.to_string(),
            Some(SWIYU_JWT_SRS_FILE.to_string()),
            disable_zk,
            low_memory_mode,
        )
        .unwrap();
        let proof = generate_noir_proof(
            SWIYU_JWT_CIRCUIT_FILE.to_string(),
            Some(SWIYU_JWT_SRS_FILE.to_string()),
            &input_json.to_string(),
            on_chain,
            vk.clone(),
            low_memory_mode,
            "SwiyuJwt",
        )
        .unwrap();
        let is_valid =
            verify_noir_proof(SWIYU_JWT_CIRCUIT_FILE.to_string(), proof, on_chain, vk, low_memory_mode)
                .unwrap();
        assert!(is_valid);
    }

    #[test]
    #[serial_test::serial]
    fn test_get_noir_verification_key_swiyu_jwt_poseidon() {
        let vk = get_noir_verification_key(
            SWIYU_JWT_CIRCUIT_FILE.to_string(),
            Some(SWIYU_JWT_SRS_FILE.to_string()),
            false, // off-chain, uses Poseidon
            false,
        );
        assert!(vk.is_ok());
        assert!(!vk.unwrap().is_empty());
    }

    #[test]
    #[serial_test::serial]
    fn test_get_noir_verification_key_swiyu_jwt_keccak() {
        let vk = get_noir_verification_key(
            SWIYU_JWT_CIRCUIT_FILE.to_string(),
            Some(SWIYU_JWT_SRS_FILE.to_string()),
            true, // on-chain, uses Keccak
            false,
        );
        assert!(vk.is_ok());
        assert!(!vk.unwrap().is_empty());
    }

    #[test]
    #[serial_test::serial]
    fn test_noir_app_macro_swiyu_jwt() {
        let low_memory_mode = false;
        let vk_offchain = get_noir_verification_key(
            SWIYU_JWT_CIRCUIT_FILE.to_string(),
            Some(SWIYU_JWT_SRS_FILE.to_string()),
            false,
            low_memory_mode,
        )
        .unwrap();
        let vk_onchain = get_noir_verification_key(
            SWIYU_JWT_CIRCUIT_FILE.to_string(),
            Some(SWIYU_JWT_SRS_FILE.to_string()),
            true,
            low_memory_mode,
        )
        .unwrap();
        let input_json: serde_json::Value = serde_json::from_str(
            &std::fs::read_to_string(concat!(TEST_VECTORS!(), "Prover.json"))
                .expect("failed to read prover"),
        )
        .expect("failed to parse prover");
        let proof_offchain = generate_noir_proof(
            SWIYU_JWT_CIRCUIT_FILE.to_string(),
            Some(SWIYU_JWT_SRS_FILE.to_string()),
            &input_json.to_string(),
            false,
            vk_offchain.clone(),
            low_memory_mode,
            "SwiyuJwt",
        );
        let proof_onchain = generate_noir_proof(
            SWIYU_JWT_CIRCUIT_FILE.to_string(),
            Some(SWIYU_JWT_SRS_FILE.to_string()),
            &input_json.to_string(),
            true,
            vk_onchain.clone(),
            low_memory_mode,
            "SwiyuJwt",
        );

        assert!(proof_offchain.is_ok());
        assert!(proof_onchain.is_ok());
        let proof_offchain = proof_offchain.unwrap();
        let proof_onchain = proof_onchain.unwrap();

        let verify_result_offchain = verify_noir_proof(
            SWIYU_JWT_CIRCUIT_FILE.to_string(),
            proof_offchain.clone(),
            false,
            vk_offchain,
            low_memory_mode,
        );
        let verify_result_onchain = verify_noir_proof(
            SWIYU_JWT_CIRCUIT_FILE.to_string(),
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
