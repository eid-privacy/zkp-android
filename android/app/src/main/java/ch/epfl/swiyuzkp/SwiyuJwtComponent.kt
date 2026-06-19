package ch.epfl.swiyuzkp

import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember
import java.io.File

@Composable
fun SwiyuJwtComponent() {
    val circuitFile = getFilePathFromAssets("noir_d10_swiyu_jwt.json")
    val srsFile = getFilePathFromAssets("noir_d10_swiyu_jwt.srs")
    val proverFile = getFilePathFromAssets("Prover.json")

    val circuitInputJson = remember {
        File(proverFile).readText()
    }

    NoirProofScreen(
        title = "Noir Swiyu JWT",
        circuit = "SwiyuJwt",
        tagPrefix = "swiyuJwt",
        circuitFile = circuitFile,
        srsFile = srsFile,
        circuitInputJson = circuitInputJson,
    )
}
