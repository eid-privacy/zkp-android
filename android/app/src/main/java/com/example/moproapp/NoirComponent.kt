package com.example.moproapp

import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Text
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import org.json.JSONArray
import org.json.JSONObject
import uniffi.mopro.generateNoirProof
import uniffi.mopro.verifyNoirProof
import uniffi.mopro.getNoirVerificationKey
import java.io.File
import java.io.InputStream

const val CREDENTIAL_STRING = "Alice                           Smith                           095834160096ae308132a110a2fdc6cd3b68658102d43a45cdd6d758586b4ad63b92dc221d4f08d8067c51d7b1a4a814e5eff0e389fb7f23110965f406286cd8e5eadac03e0000000000134a37"
val SIGNATURE_DEVICE = listOf(158, 220, 195, 163, 254, 53, 31, 79, 93, 163, 186, 252, 237, 103, 156, 223, 136, 147, 82, 111, 23, 40, 119, 72, 193, 19, 195, 44, 205, 224, 216, 21, 89, 85, 244, 178, 26, 139, 114, 226, 168, 180, 27, 10, 172, 160, 163, 102, 37, 212, 141, 92, 74, 210, 230, 158, 155, 70, 227, 32, 219, 110, 231, 152)
val CHALLENGE_HASH = listOf(32, 40, 248, 44, 225, 214, 0, 161, 197, 113, 178, 102, 73, 82, 63, 107, 176, 196, 21, 63, 254, 173, 161, 2, 166, 207, 60, 95, 239, 86, 9, 61)

@Composable
fun NoirComponent() {
    val context = LocalContext.current
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

    val circuitFile = getFilePathFromAssets("noir_c03_holder_binding.json")
    val srsFile = getFilePathFromAssets("noir_c03_holder_binding.srs")

    // Build the JSON input for the HolderBinding circuit
    val circuitInputJson = remember {
        val json = JSONObject()
        json.put("credential_string", CREDENTIAL_STRING)

        val signatureDevice = JSONArray()
        SIGNATURE_DEVICE.forEach { signatureDevice.put(it) }
        json.put("signature_device", signatureDevice)

        val challengeHash = JSONArray()
        CHALLENGE_HASH.forEach { challengeHash.put(it) }
        json.put("challenge_hash", challengeHash)

        json.toString()
    }

    Box(modifier = Modifier.fillMaxSize().padding(16.dp), contentAlignment = Alignment.Center) {
        Column(horizontalAlignment = Alignment.CenterHorizontally) {
            Text(
                text = "Noir Holder Binding",
                modifier = Modifier.padding(bottom = 20.dp),
                fontWeight = FontWeight.Bold,
                fontSize = 22.sp
            )

            // Status message with prominent styling
            Text(
                text = statusMessage,
                modifier = Modifier.padding(bottom = 24.dp),
                textAlign = TextAlign.Center,
                fontSize = 16.sp,
                fontWeight = if (isGeneratingProof || isVerifyingProof) FontWeight.Bold else FontWeight.Normal
            )

            // Progress indicator when operations are running
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
                                val onChain = true  // Use Keccak for Solidity compatibility
                                val lowMemoryMode = false
                                val circuit = "HolderBinding"

                                // Generate verification key (circuit changed, so pre-generated VK is unreliable)
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
                modifier = Modifier.padding(top = 20.dp).testTag("noirGenerateProofButton"),
                enabled = !isGeneratingProof && !isVerifyingProof
            ) { 
                Text(text = "Generate Proof")
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
                                        val onChain = true  // Use Keccak for Solidity compatibility
                                        val lowMemoryMode = false

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
                modifier = Modifier.padding(top = 20.dp).testTag("noirVerifyProofButton"),
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
