package ch.epfl.swiyuzkp

import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember
import org.json.JSONObject

@Composable
fun IssuerSignatureComponent() {
    val circuitFile = getFilePathFromAssets("noir_c04_issuer_signature.json")
    val srsFile = getFilePathFromAssets("noir_c04_issuer_signature.srs")

    val circuitInputJson = remember {
        JSONObject().apply {
            put("credential_string", CREDENTIAL_STRING)
            put("signature_issuer", SIGNATURE_ISSUER.toJsonArray())
            put("pubkey_issuer_x", PUBKEY_ISSUER_X.toJsonArray())
            put("pubkey_issuer_y", PUBKEY_ISSUER_Y.toJsonArray())
        }.toString()
    }

    NoirProofScreen(
        title = "Noir Issuer Signature",
        circuit = "IssuerSignature",
        tagPrefix = "issuerSignature",
        circuitFile = circuitFile,
        srsFile = srsFile,
        circuitInputJson = circuitInputJson,
    )
}
