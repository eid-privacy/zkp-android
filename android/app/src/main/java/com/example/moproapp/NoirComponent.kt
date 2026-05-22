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

// input
// Prover_0
const val CREDENTIAL_STRING = "Alice                           Smith                           095834160096ae308132a110a2fdc6cd3b68658102d43a45cdd6d758586b4ad63b92dc221d4f08d8067c51d7b1a4a814e5eff0e389fb7f23110965f406286cd8e5eadac03e0000000000134a37"
val SIGNATURE_DEVICE = listOf(158, 220, 195, 163, 254, 53, 31, 79, 93, 163, 186, 252, 237, 103, 156, 223, 136, 147, 82, 111, 23, 40, 119, 72, 193, 19, 195, 44, 205, 224, 216, 21, 89, 85, 244, 178, 26, 139, 114, 226, 168, 180, 27, 10, 172, 160, 163, 102, 37, 212, 141, 92, 74, 210, 230, 158, 155, 70, 227, 32, 219, 110, 231, 152)
val CHALLENGE_HASH = listOf(32, 40, 248, 44, 225, 214, 0, 161, 197, 113, 178, 102, 73, 82, 63, 107, 176, 196, 21, 63, 254, 173, 161, 2, 166, 207, 60, 95, 239, 86, 9, 61)
const val CURRENT_DATE = 1762449600L
val PUBKEY_ISSUER_X = listOf(126, 248, 106, 31, 85, 42, 214, 184, 182, 133, 99, 87, 93, 36, 227, 150, 248, 59, 139, 226, 147, 161, 12, 54, 239, 26, 245, 148, 118, 133, 77, 8)
val PUBKEY_ISSUER_Y = listOf(209, 78, 91, 83, 6, 68, 60, 60, 249, 26, 250, 42, 66, 55, 166, 202, 77, 147, 71, 8, 246, 169, 110, 76, 139, 254, 162, 163, 96, 251, 115, 69)
val SIGNATURE_ISSUER = listOf(238, 166, 185, 25, 45, 42, 145, 240, 143, 160, 111, 109, 229, 64, 72, 151, 236, 118, 97, 17, 42, 125, 19, 240, 163, 114, 20, 56, 139, 58, 86, 17, 88, 102, 202, 59, 253, 200, 232, 45, 44, 234, 48, 76, 157, 88, 242, 122, 60, 19, 132, 177, 144, 245, 176, 248, 150, 14, 166, 161, 27, 205, 54, 253)
val REVOCATION_LIST = listOf(0, 0, 0, 0, 0, 19, 72, 0, 0, 0, 0, 0, 105, 12, 216, 192, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 105, 77, 116, 25, 18, 94, 156, 30, 23, 239, 142, 116, 96, 124, 232, 193, 10, 107, 181, 126, 56, 6, 22, 52, 44, 138, 27, 170, 216, 208, 91, 199, 107, 36, 99, 121, 197, 183, 57, 215, 181, 235, 25, 149, 0, 188, 92, 158, 224, 75, 54, 4, 35, 137, 54, 24, 74, 91, 228, 185, 108, 203, 18, 236)

@Composable
fun HolderBindingComponent() {
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
                                val onChain = true  // Use Keccak for Solidity compatibility
                                val lowMemoryMode = false
                                val circuit = "HolderBinding"

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
                modifier = Modifier.padding(top = 20.dp).testTag("holderBindingGenerateProofButton"),
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
                                val onChain = true  // Use Keccak for Solidity compatibility
                                val lowMemoryMode = false
                                val circuit = "HolderBinding"

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
                modifier = Modifier.padding(top = 20.dp).testTag("holderBindingBenchmarkProofButton"),
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
                modifier = Modifier.padding(top = 20.dp).testTag("holderBindingVerifyProofButton"),
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

@Composable
fun IssuerSignatureComponent() {
    val context = LocalContext.current
    var provingTime by remember { mutableStateOf("") }
    var proofResult by remember { mutableStateOf("") }
    var verificationTime by remember { mutableStateOf("") }
    var verificationResult by remember { mutableStateOf("") }
    var proofBytes by remember { mutableStateOf<ByteArray?>(null) }
    var verificationKey by remember { mutableStateOf<ByteArray?>(null) }

    var isGeneratingProof by remember { mutableStateOf(false) }
    var isVerifyingProof by remember { mutableStateOf(false) }
    var statusMessage by remember { mutableStateOf("Ready to generate proof") }

    val circuitFile = getFilePathFromAssets("noir_c04_issuer_signature.json")
    val srsFile = getFilePathFromAssets("noir_c04_issuer_signature.srs")

    val circuitInputJson = remember {
        val json = JSONObject()
        json.put("credential_string", CREDENTIAL_STRING)

        val signatureIssuer = JSONArray()
        SIGNATURE_ISSUER.forEach { signatureIssuer.put(it) }
        json.put("signature_issuer", signatureIssuer)

        val pubkeyIssuerX = JSONArray()
        PUBKEY_ISSUER_X.forEach { pubkeyIssuerX.put(it) }
        json.put("pubkey_issuer_x", pubkeyIssuerX)

        val pubkeyIssuerY = JSONArray()
        PUBKEY_ISSUER_Y.forEach { pubkeyIssuerY.put(it) }
        json.put("pubkey_issuer_y", pubkeyIssuerY)

        json.toString()
    }

    Box(modifier = Modifier.fillMaxSize().padding(16.dp), contentAlignment = Alignment.Center) {
        Column(horizontalAlignment = Alignment.CenterHorizontally) {
            Text(
                text = "Noir Issuer Signature",
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
                                val onChain = true
                                val lowMemoryMode = false
                                val circuit = "IssuerSignature"

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
                modifier = Modifier.padding(top = 20.dp).testTag("issuerSignatureGenerateProofButton"),
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
                                val onChain = true  // Use Keccak for Solidity compatibility
                                val lowMemoryMode = false
                                val circuit = "IssuerSignature"

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
                modifier = Modifier.padding(top = 20.dp).testTag("issuerSignatureBenchmarkProofButton"),
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
                                        val onChain = true
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
                modifier = Modifier.padding(top = 20.dp).testTag("issuerSignatureVerifyProofButton"),
                enabled = !isGeneratingProof && !isVerifyingProof && proofBytes != null
            ) {
                Text(text = "Verify Proof")
            }

            Spacer(modifier = Modifier.height(40.dp))

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

@Composable
fun AgeVerificationComponent() {
    val context = LocalContext.current
    var provingTime by remember { mutableStateOf("") }
    var proofResult by remember { mutableStateOf("") }
    var verificationTime by remember { mutableStateOf("") }
    var verificationResult by remember { mutableStateOf("") }
    var proofBytes by remember { mutableStateOf<ByteArray?>(null) }
    var verificationKey by remember { mutableStateOf<ByteArray?>(null) }

    var isGeneratingProof by remember { mutableStateOf(false) }
    var isVerifyingProof by remember { mutableStateOf(false) }
    var statusMessage by remember { mutableStateOf("Ready to generate proof") }

    val circuitFile = getFilePathFromAssets("noir_c05_age_verification.json")
    val srsFile = getFilePathFromAssets("noir_c05_age_verification.srs")

    val circuitInputJson = remember {
        val json = JSONObject()
        json.put("credential_string", CREDENTIAL_STRING)
        json.put("current_date", CURRENT_DATE)
        json.toString()
    }

    Box(modifier = Modifier.fillMaxSize().padding(16.dp), contentAlignment = Alignment.Center) {
        Column(horizontalAlignment = Alignment.CenterHorizontally) {
            Text(
                text = "Noir Age Verification",
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
                                val onChain = true
                                val lowMemoryMode = false
                                val circuit = "AgeVerification"

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
                modifier = Modifier.padding(top = 20.dp).testTag("ageVerificationGenerateProofButton"),
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
                                val onChain = true  // Use Keccak for Solidity compatibility
                                val lowMemoryMode = false
                                val circuit = "AgeVerification"

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
                modifier = Modifier.padding(top = 20.dp).testTag("ageVerificationBenchmarkProofButton"),
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
                                        val onChain = true
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
                modifier = Modifier.padding(top = 20.dp).testTag("ageVerificationVerifyProofButton"),
                enabled = !isGeneratingProof && !isVerifyingProof && proofBytes != null
            ) {
                Text(text = "Verify Proof")
            }

            Spacer(modifier = Modifier.height(40.dp))

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

@Composable
fun NonRevocationComponent() {
    val context = LocalContext.current
    var provingTime by remember { mutableStateOf("") }
    var proofResult by remember { mutableStateOf("") }
    var verificationTime by remember { mutableStateOf("") }
    var verificationResult by remember { mutableStateOf("") }
    var proofBytes by remember { mutableStateOf<ByteArray?>(null) }
    var verificationKey by remember { mutableStateOf<ByteArray?>(null) }

    var isGeneratingProof by remember { mutableStateOf(false) }
    var isVerifyingProof by remember { mutableStateOf(false) }
    var statusMessage by remember { mutableStateOf("Ready to generate proof") }

    val circuitFile = getFilePathFromAssets("noir_c06_non_revocation.json")
    val srsFile = getFilePathFromAssets("noir_c06_non_revocation.srs")

    val circuitInputJson = remember {
        val json = JSONObject()
        json.put("credential_string", CREDENTIAL_STRING)

        val revocationList = JSONArray()
        REVOCATION_LIST.forEach { revocationList.put(it) }
        json.put("revocation_list", revocationList)

        json.put("current_date", CURRENT_DATE)

        val pubkeyIssuerX = JSONArray()
        PUBKEY_ISSUER_X.forEach { pubkeyIssuerX.put(it) }
        json.put("pubkey_issuer_x", pubkeyIssuerX)

        val pubkeyIssuerY = JSONArray()
        PUBKEY_ISSUER_Y.forEach { pubkeyIssuerY.put(it) }
        json.put("pubkey_issuer_y", pubkeyIssuerY)

        json.toString()
    }

    Box(modifier = Modifier.fillMaxSize().padding(16.dp), contentAlignment = Alignment.Center) {
        Column(horizontalAlignment = Alignment.CenterHorizontally) {
            Text(
                text = "Noir Non Revocation",
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
                                val onChain = true
                                val lowMemoryMode = false
                                val circuit = "NonRevocation"

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
                modifier = Modifier.padding(top = 20.dp).testTag("nonRevocationGenerateProofButton"),
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
                                val onChain = true  // Use Keccak for Solidity compatibility
                                val lowMemoryMode = false
                                val circuit = "NonRevocation"

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
                modifier = Modifier.padding(top = 20.dp).testTag("nonRevocationBenchmarkProofButton"),
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
                                        val onChain = true
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
                modifier = Modifier.padding(top = 20.dp).testTag("nonRevocationVerifyProofButton"),
                enabled = !isGeneratingProof && !isVerifyingProof && proofBytes != null
            ) {
                Text(text = "Verify Proof")
            }

            Spacer(modifier = Modifier.height(40.dp))

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

@Composable
fun FullProofComponent() {
    val context = LocalContext.current
    var provingTime by remember { mutableStateOf("") }
    var proofResult by remember { mutableStateOf("") }
    var verificationTime by remember { mutableStateOf("") }
    var verificationResult by remember { mutableStateOf("") }
    var proofBytes by remember { mutableStateOf<ByteArray?>(null) }
    var verificationKey by remember { mutableStateOf<ByteArray?>(null) }

    var isGeneratingProof by remember { mutableStateOf(false) }
    var isVerifyingProof by remember { mutableStateOf(false) }
    var statusMessage by remember { mutableStateOf("Ready to generate proof") }

    val circuitFile = getFilePathFromAssets("noir_c09_full_proof.json")
    val srsFile = getFilePathFromAssets("noir_c09_full_proof.srs")

    val circuitInputJson = remember {
        val json = JSONObject()
        json.put("credential_string", CREDENTIAL_STRING)

        val revocationList = JSONArray()
        REVOCATION_LIST.forEach { revocationList.put(it) }
        json.put("revocation_list", revocationList)

        val signatureDevice = JSONArray()
        SIGNATURE_DEVICE.forEach { signatureDevice.put(it) }
        json.put("signature_device", signatureDevice)

        val signatureIssuer = JSONArray()
        SIGNATURE_ISSUER.forEach { signatureIssuer.put(it) }
        json.put("signature_issuer", signatureIssuer)

        val challengeHash = JSONArray()
        CHALLENGE_HASH.forEach { challengeHash.put(it) }
        json.put("challenge_hash", challengeHash)

        json.put("current_date", CURRENT_DATE)

        val pubkeyIssuerX = JSONArray()
        PUBKEY_ISSUER_X.forEach { pubkeyIssuerX.put(it) }
        json.put("pubkey_issuer_x", pubkeyIssuerX)

        val pubkeyIssuerY = JSONArray()
        PUBKEY_ISSUER_Y.forEach { pubkeyIssuerY.put(it) }
        json.put("pubkey_issuer_y", pubkeyIssuerY)

        json.toString()
    }

    Box(modifier = Modifier.fillMaxSize().padding(16.dp), contentAlignment = Alignment.Center) {
        Column(horizontalAlignment = Alignment.CenterHorizontally) {
            Text(
                text = "Noir Full Proof",
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
                                val onChain = true
                                val lowMemoryMode = false
                                val circuit = "FullProof"

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
                modifier = Modifier.padding(top = 20.dp).testTag("fullProofGenerateProofButton"),
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
                                val onChain = true  // Use Keccak for Solidity compatibility
                                val lowMemoryMode = false
                                val circuit = "FullProof"

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
                modifier = Modifier.padding(top = 20.dp).testTag("fullProofBenchmarkProofButton"),
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
                                        val onChain = true
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
                modifier = Modifier.padding(top = 20.dp).testTag("fullProofVerifyProofButton"),
                enabled = !isGeneratingProof && !isVerifyingProof && proofBytes != null
            ) {
                Text(text = "Verify Proof")
            }

            Spacer(modifier = Modifier.height(40.dp))

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
