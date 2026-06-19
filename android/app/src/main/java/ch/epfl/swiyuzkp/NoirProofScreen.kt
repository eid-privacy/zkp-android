package ch.epfl.swiyuzkp

import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Text
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import uniffi.mopro.generateNoirProof
import uniffi.mopro.verifyNoirProof
import uniffi.mopro.getNoirVerificationKey

/**
 * Reusable screen for every Noir credential circuit. All six circuits share the same
 * generate / benchmark / verify flow; only the title, circuit name, asset paths and the
 * input JSON differ, so they are passed in by each per-circuit component.
 *
 * @param title             Heading shown at the top of the screen.
 * @param circuit           Circuit identifier passed to [generateNoirProof].
 * @param tagPrefix         Prefix for the button test tags (e.g. "holderBinding").
 * @param circuitFile       Resolved path to the circuit `.json` asset.
 * @param srsFile           Resolved path to the `.srs` asset.
 * @param circuitInputJson  Pre-built JSON input for the circuit.
 */
@Composable
fun NoirProofScreen(
    title: String,
    circuit: String,
    tagPrefix: String,
    circuitFile: String,
    srsFile: String,
    circuitInputJson: String,
) {
    var provingTime by remember { mutableStateOf("") }
    var proofResult by remember { mutableStateOf("") }
    var verificationTime by remember { mutableStateOf("") }
    var verificationResult by remember { mutableStateOf("") }
    var proofBytes by remember { mutableStateOf<ByteArray?>(null) }
    var verificationKey by remember { mutableStateOf<ByteArray?>(null) }

    // Status states
    var isGeneratingProof by remember { mutableStateOf(false) }
    var isVerifyingProof by remember { mutableStateOf(false) }
    var statusMessage by remember { mutableStateOf("Ready to generate proof") }

    // Use Keccak for Solidity compatibility.
    val onChain = true
    val lowMemoryMode = false

    Box(modifier = Modifier.fillMaxSize().padding(16.dp), contentAlignment = Alignment.Center) {
        Column(
            modifier = Modifier.verticalScroll(rememberScrollState()),
            horizontalAlignment = Alignment.CenterHorizontally
        ) {
            Text(
                text = title,
                modifier = Modifier.padding(bottom = 20.dp),
                fontWeight = FontWeight.Bold,
                fontSize = 22.sp
            )

            Text(
                text = statusMessage,
                modifier = Modifier.padding(bottom = 24.dp),
                textAlign = TextAlign.Center,
                fontSize = 16.sp,
                fontWeight = if (isGeneratingProof || isVerifyingProof) FontWeight.Bold else FontWeight.Normal
            )

            if (isGeneratingProof || isVerifyingProof) {
                CircularProgressIndicator(
                    modifier = Modifier.padding(bottom = 16.dp)
                )
            }

            Button(
                onClick = {
                    isGeneratingProof = true
                    provingTime = ""
                    proofResult = ""
                    statusMessage = "Generating proof... This may take some time"

                    Thread(
                        Runnable {
                            try {
                                statusMessage = "Generating verification key..."
                                val vk = getNoirVerificationKey(circuitFile, srsFile, onChain, lowMemoryMode)
                                verificationKey = vk

                                statusMessage = "Generating proof with verification key..."
                                val startTime = System.currentTimeMillis()
                                proofBytes = generateNoirProof(
                                    circuitFile,
                                    srsFile,
                                    circuitInputJson,
                                    onChain,
                                    vk,
                                    lowMemoryMode,
                                    circuit
                                )
                                val endTime = System.currentTimeMillis()
                                val duration = endTime - startTime

                                provingTime = "Proving time: $duration ms"
                                proofResult = "Proof generated: ${proofBytes?.size ?: 0} bytes"
                                statusMessage = "Proof generation completed"
                            } catch (e: Exception) {
                                provingTime = "Proving failed"
                                proofResult = "Error: ${e.message}"
                                statusMessage = "Proof generation failed"
                                e.printStackTrace()
                            } finally {
                                isGeneratingProof = false
                            }
                        }
                    ).start()
                },
                modifier = Modifier.padding(top = 20.dp).testTag("${tagPrefix}GenerateProofButton"),
                enabled = !isGeneratingProof && !isVerifyingProof
            ) {
                Text(text = "Generate Proof")
            }

            Spacer(modifier = Modifier.height(16.dp))

            Button(
                onClick = {
                    isGeneratingProof = true
                    provingTime = ""
                    proofResult = ""
                    statusMessage = "Generating proof... This may take some time"

                    Thread(
                        Runnable {
                            try {
                                statusMessage = "Generating verification key..."
                                val vk = getNoirVerificationKey(circuitFile, srsFile, onChain, lowMemoryMode)
                                verificationKey = vk

                                statusMessage = "Benchmarking proof generation with verification key..."
                                var totalDuration = 0L
                                var bestDuration = 0L
                                var worstDuration = 0L
                                for (i in 0 until 100) {
                                    statusMessage = "Run ${i + 1} of 100"

                                    val startTime = System.currentTimeMillis()
                                    proofBytes = generateNoirProof(
                                        circuitFile,
                                        srsFile,
                                        circuitInputJson,
                                        onChain,
                                        vk,
                                        lowMemoryMode,
                                        circuit
                                    )
                                    val endTime = System.currentTimeMillis()
                                    val duration = endTime - startTime
                                    if ((bestDuration == 0L) || (duration < bestDuration)) bestDuration = duration
                                    if ((worstDuration == 0L) || (worstDuration < duration)) worstDuration = duration
                                    totalDuration += duration
                                    println("Run ${i + 1} of 100 proving time: $duration ms")
                                }
                                val averageDuration = totalDuration / 100
                                provingTime = "Proving time: $averageDuration ms (average of 100 runs)"
                                println("Proving time: $averageDuration ms (average of 100 runs)")
                                println("Best proving time: $bestDuration ms (average of 100 runs)")
                                println("Worst proving time: $worstDuration ms (average of 100 runs)")
                                statusMessage = "Proof generation completed"
                            } catch (e: Exception) {
                                provingTime = "Benchmarking failed"
                                proofResult = "Error: ${e.message}"
                                statusMessage = "Benchmarking proof generation failed"
                                e.printStackTrace()
                            } finally {
                                isGeneratingProof = false
                            }
                        }
                    ).start()
                },
                modifier = Modifier.padding(top = 20.dp).testTag("${tagPrefix}BenchmarkProofButton"),
                enabled = !isGeneratingProof && !isVerifyingProof
            ) {
                Text(text = "Benchmark Proof Generation")
            }

            Spacer(modifier = Modifier.height(16.dp))

            Button(
                onClick = {
                    isVerifyingProof = true
                    verificationTime = ""
                    verificationResult = ""
                    statusMessage = "Verifying proof..."

                    Thread(
                        Runnable {
                            try {
                                proofBytes?.let { proof ->
                                    verificationKey?.let { vk ->
                                        val startTime = System.currentTimeMillis()
                                        val result = verifyNoirProof(
                                            circuitFile,
                                            proof,
                                            onChain,
                                            vk,
                                            lowMemoryMode
                                        )
                                        val endTime = System.currentTimeMillis()
                                        val duration = endTime - startTime

                                        verificationTime = "Verification time: $duration ms"
                                        verificationResult = "Verification result: $result"
                                        if (result)
                                            statusMessage = "Proof verified successfully!"
                                        else
                                            statusMessage = "Proof verification failed!"
                                    } ?: run {
                                        verificationResult = "No verification key available"
                                        statusMessage = "Please generate a proof first to get verification key"
                                    }
                                } ?: run {
                                    verificationResult = "No proof available"
                                    statusMessage = "Please generate a proof first"
                                }
                            } catch (e: Exception) {
                                verificationTime = "Verification failed"
                                verificationResult = "Error: ${e.message}"
                                statusMessage = "Proof verification error"
                                e.printStackTrace()
                            } finally {
                                isVerifyingProof = false
                            }
                        }
                    ).start()
                },
                modifier = Modifier.padding(top = 20.dp).testTag("${tagPrefix}VerifyProofButton"),
                enabled = !isGeneratingProof && !isVerifyingProof && proofBytes != null
            ) {
                Text(text = "Verify Proof")
            }

            Spacer(modifier = Modifier.height(40.dp))

            // Results displayed in a more organized way
            if (provingTime.isNotEmpty() || proofResult.isNotEmpty() ||
                verificationTime.isNotEmpty() || verificationResult.isNotEmpty()) {

                Text(
                    text = "Results",
                    fontWeight = FontWeight.Bold,
                    fontSize = 18.sp,
                    modifier = Modifier.padding(bottom = 8.dp)
                )

                if (provingTime.isNotEmpty()) {
                    Text(
                        text = provingTime,
                        modifier = Modifier.padding(top = 4.dp).width(280.dp),
                        textAlign = TextAlign.Center
                    )
                }

                if (proofResult.isNotEmpty()) {
                    Text(
                        text = proofResult,
                        modifier = Modifier.padding(top = 4.dp).width(280.dp),
                        textAlign = TextAlign.Center
                    )
                }

                if (verificationTime.isNotEmpty()) {
                    Text(
                        text = verificationTime,
                        modifier = Modifier.padding(top = 4.dp).width(280.dp),
                        textAlign = TextAlign.Center
                    )
                }

                if (verificationResult.isNotEmpty()) {
                    Text(
                        text = verificationResult,
                        modifier = Modifier.padding(top = 4.dp).width(280.dp),
                        textAlign = TextAlign.Center,
                        fontWeight = if (verificationResult.contains("true")) FontWeight.Bold else FontWeight.Normal
                    )
                }
            }
        }
    }
}
