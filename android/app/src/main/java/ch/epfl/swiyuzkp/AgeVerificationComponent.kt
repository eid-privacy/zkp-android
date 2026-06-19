package ch.epfl.swiyuzkp

import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember
import org.json.JSONObject

@Composable
fun AgeVerificationComponent() {
    val circuitFile = getFilePathFromAssets("noir_c05_age_verification.json")
    val srsFile = getFilePathFromAssets("noir_c05_age_verification.srs")

    val circuitInputJson = remember {
        JSONObject().apply {
            put("credential_string", CREDENTIAL_STRING)
            put("current_date", CURRENT_DATE)
        }.toString()
    }

    NoirProofScreen(
        title = "Noir Age Verification",
        circuit = "AgeVerification",
        tagPrefix = "ageVerification",
        circuitFile = circuitFile,
        srsFile = srsFile,
        circuitInputJson = circuitInputJson,
    )
}
