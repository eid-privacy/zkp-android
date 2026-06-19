package ch.epfl.swiyuzkp

import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember
import org.json.JSONObject

@Composable
fun HolderBindingComponent() {
    val circuitFile = getFilePathFromAssets("noir_c03_holder_binding.json")
    val srsFile = getFilePathFromAssets("noir_c03_holder_binding.srs")

    val circuitInputJson = remember {
        JSONObject().apply {
            put("credential_string", CREDENTIAL_STRING)
            put("signature_device", SIGNATURE_DEVICE.toJsonArray())
            put("challenge_hash", CHALLENGE_HASH.toJsonArray())
        }.toString()
    }

    NoirProofScreen(
        title = "Noir Holder Binding",
        circuit = "HolderBinding",
        tagPrefix = "holderBinding",
        circuitFile = circuitFile,
        srsFile = srsFile,
        circuitInputJson = circuitInputJson,
    )
}
