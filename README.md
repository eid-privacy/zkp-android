# zkp-android

## Overview

`zkp-android` is an Android application that demonstrates Zero-Knowledge Proof (ZKP) generation and verification across multiple proof systems (Circom, Halo2, and Noir). The project is built with the `mopro` toolchain, which generates cross-platform bindings from Rust source code to Kotlin (Android) via UniFFI and JNA.

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
cp proofs/c03_holder_binding/vk ../../zkp-android/test-vectors/noir/noir_c03_holder_binding.vk
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
```

## Test

Run tests before building bindings

```sh
curl -L https://repo1.maven.org/maven2/net/java/dev/jna/jna/5.13.0/jna-5.13.0.jar -o jna-5.13.0.jar
export CLASSPATH=jna-5.13.0.jar
cargo test
```
