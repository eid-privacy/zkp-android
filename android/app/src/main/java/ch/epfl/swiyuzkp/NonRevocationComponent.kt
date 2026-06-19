package ch.epfl.swiyuzkp

import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember
import org.json.JSONObject

@Composable
fun NonRevocationComponent() {
    val circuitFile = getFilePathFromAssets("noir_c06_non_revocation.json")
    val srsFile = getFilePathFromAssets("noir_c06_non_revocation.srs")

    val circuitInputJson = remember {
        JSONObject().apply {
            put("credential_string", CREDENTIAL_STRING)
            put("revocation_list", REVOCATION_LIST.toJsonArray())
            put("current_date", CURRENT_DATE)
            put("pubkey_issuer_x", PUBKEY_ISSUER_X.toJsonArray())
            put("pubkey_issuer_y", PUBKEY_ISSUER_Y.toJsonArray())
        }.toString()
    }

    NoirProofScreen(
        title = "Noir Non Revocation",
        circuit = "NonRevocation",
        tagPrefix = "nonRevocation",
        circuitFile = circuitFile,
        srsFile = srsFile,
        circuitInputJson = circuitInputJson,
    )
}
