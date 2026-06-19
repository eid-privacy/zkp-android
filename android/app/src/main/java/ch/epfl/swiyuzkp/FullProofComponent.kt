package ch.epfl.swiyuzkp

import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember
import org.json.JSONObject

@Composable
fun FullProofComponent() {
    val circuitFile = getFilePathFromAssets("noir_c09_full_proof.json")
    val srsFile = getFilePathFromAssets("noir_c09_full_proof.srs")

    val circuitInputJson = remember {
        JSONObject().apply {
            put("credential_string", CREDENTIAL_STRING)
            put("revocation_list", REVOCATION_LIST.toJsonArray())
            put("signature_device", SIGNATURE_DEVICE.toJsonArray())
            put("signature_issuer", SIGNATURE_ISSUER.toJsonArray())
            put("challenge_hash", CHALLENGE_HASH.toJsonArray())
            put("current_date", CURRENT_DATE)
            put("pubkey_issuer_x", PUBKEY_ISSUER_X.toJsonArray())
            put("pubkey_issuer_y", PUBKEY_ISSUER_Y.toJsonArray())
        }.toString()
    }

    NoirProofScreen(
        title = "Noir Full Proof",
        circuit = "FullProof",
        tagPrefix = "fullProof",
        circuitFile = circuitFile,
        srsFile = srsFile,
        circuitInputJson = circuitInputJson,
    )
}
