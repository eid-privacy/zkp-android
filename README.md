# zkp-android

## Overview

`zkp-android` is an Android application that demonstrates Noir Zero-Knowledge Proof (ZKP) generation and verification. The project is built with the `mopro` toolchain, which generates cross-platform bindings from Rust source code to Kotlin (Android) via UniFFI and JNA.

## Prerequisites

```
.
├── flakes
├── noir-rs
├── zkp-android
└── zkp-pocs
```

1. install [Install Android Studio](https://developer.android.com/studio/install)
2. install the [Android Native Development Kit (NDK)](https://developer.android.com/studio/projects/install-ndk) and set `ANDROID_NDK_HOME` to its install location
3. install Kotlin

## Set up

1. `cargo install mopro-cli`
2. `mopro build`
3. `mopro create`
4. `mopro update`
5. `studio android/`

## Update bindings

(automatically)

```sh
mopro build --auto-update
```

(manually)

```sh
mopro update
```

## Set up circuit and download .srs

```bash
cd zkp-pocs/noir/;
make
cp c03_holder_binding/target/c03_holder_binding.json ../../zkp-android/test-vectors/noir/noir_c03_holder_binding.json
cp c03_holder_binding/target/c03_holder_binding.json ../../zkp-android/android/app/src/main/assets/noir_c03_holder_binding.json
cp c04_issuer_signature/target/c04_issuer_signature.json ../../zkp-android/test-vectors/noir/noir_c04_issuer_signature.json
cp c04_issuer_signature/target/c04_issuer_signature.json ../../zkp-android/android/app/src/main/assets/noir_c04_issuer_signature.json
cp c05_age_verification/target/c05_age_verification.json ../../zkp-android/test-vectors/noir/noir_c05_age_verification.json
cp c05_age_verification/target/c05_age_verification.json ../../zkp-android/android/app/src/main/assets/noir_c05_age_verification.json
cp c06_non_revocation/target/c06_non_revocation.json ../../zkp-android/test-vectors/noir/noir_c06_non_revocation.json
cp c06_non_revocation/target/c06_non_revocation.json ../../zkp-android/android/app/src/main/assets/noir_c06_non_revocation.json
cp c09_full_proof/target/c09_full_proof.json ../../zkp-android/test-vectors/noir/noir_c09_full_proof.json
cp c09_full_proof/target/c09_full_proof.json ../../zkp-android/android/app/src/main/assets/noir_c09_full_proof.json
cp d10_swiyu_jwt/target/d10_swiyu_jwt.json ../../zkp-android/test-vectors/noir/noir_d10_swiyu_jwt.json
```

```sh
git clone https://github.com/zkmopro/noir-rs/
cd noir-rs
```

Default size (2^18):

```sh
cargo run --bin srs_downloader --features srs-downloader -- -o zkp-android/test-vectors/noir/noir_c03_holder_binding.srs
```

Specific circuit:

```sh
cargo run --bin srs_downloader --features srs-downloader -- -c ../zkp-android/test-vectors/noir/noir_c03_holder_binding.json -o ../zkp-android/test-vectors/noir/noir_c03_holder_binding.srs
cp ../zkp-android/test-vectors/noir/noir_c03_holder_binding.srs ../../zkp-android/android/app/src/main/assets/noir_c03_holder_binding.srs
cargo run --bin srs_downloader --features srs-downloader -- -c ../zkp-android/test-vectors/noir/noir_c04_issuer_signature.json -o ../zkp-android/test-vectors/noir/noir_c04_issuer_signature.srs
cp ../zkp-android/test-vectors/noir/noir_c04_issuer_signature.srs ../../zkp-android/android/app/src/main/assets/noir_c04_issuer_signature.srs
cargo run --bin srs_downloader --features srs-downloader -- -c ../zkp-android/test-vectors/noir/noir_c05_age_verification.json -o ../zkp-android/test-vectors/noir/noir_c05_age_verification.srs
cp ../zkp-android/test-vectors/noir/noir_c05_age_verification.srs ../../zkp-android/android/app/src/main/assets/noir_c05_age_verification.srs
cargo run --bin srs_downloader --features srs-downloader -- -c ../zkp-android/test-vectors/noir/noir_c06_non_revocation.json -o ../zkp-android/test-vectors/noir/noir_c06_non_revocation.srs
cp ../zkp-android/test-vectors/noir/noir_c06_non_revocation.srs ../../zkp-android/android/app/src/main/assets/noir_c06_non_revocation.srs
cargo run --bin srs_downloader --features srs-downloader -- -c ../zkp-android/test-vectors/noir/noir_c09_full_proof.json -o ../zkp-android/test-vectors/noir/noir_c09_full_proof.srs
cp ../zkp-android/test-vectors/noir/noir_c09_full_proof.srs ../../zkp-android/android/app/src/main/assets/noir_c09_full_proof.srs
cargo run --bin srs_downloader --features srs-downloader -- -c ../zkp-android/test-vectors/noir/noir_d10_swiyu_jwt.json -o ../zkp-android/test-vectors/noir/noir_d10_swiyu_jwt.srs
```

## Test

Run tests before building bindings

```sh
curl -L https://repo1.maven.org/maven2/net/java/dev/jna/jna/5.13.0/jna-5.13.0.jar -o jna-5.13.0.jar
export CLASSPATH=jna-5.13.0.jar
cargo test
```
