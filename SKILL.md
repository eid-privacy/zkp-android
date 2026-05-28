---
name: integrate-circuit-rust
description: Integrate cryptographic circuit into Rust tests
---

# Integrate cryptographic circuit into Rust tests

## Steps:

1. look for the cryptographic circuit files (`.json` and related `.srs`) in `./test-vectors/noir/`
2. the circuit file should have an associated ` get_*_abi` function as well as associated tests in `./src/noir.rs`

    1. if this is the case, you don't have to edit `./src/noir.rs`
    2. if not, check that the related input is defined in `./src/noir.rs`

        1. if this is the case, add the `get_*_abi` function and the associated tests
        2. if this is not the case, add the `get_*_abi` function and the associated tests but leave a comment where the input would be

3. the circuit file should have an associated test in `./src/lib.rs`
    1. if this is the case, you don't have to edit `./src/lib.rs`
    2. if not, add the associated test

## Rules:

- any new functions or tests should closely mirror the corresponding functions and tests of the existing cryptographic circuits
- do not refactor any code

---
name: integrate-circuit-android
description: Integrate cryptographic circuit into Android app
---

# Integrate cryptographic circuit into Android app

## Steps:

1. look for the cryptographic circuit files (`.json` and related `.srs`) and any other related files (such as `Prover.json`) in `./test-vectors/noir/`
2. if they are not present in `./android/app/src/main/assets/`, copy them there
3. edit the following files

        - `android/app/src/androidTest/java/com/example/moproapp/ExampleInstrumentedTest.kt`
        - `android/app/src/main/java/com/example/moproapp/MainActivity.kt`
        - `android/app/src/main/java/com/example/moproapp/NoirComponent.kt`

    to add the same functionality for the new circuit as for the existing circuits

## Rules:

- any new functions or tests should closely mirror the corresponding functions and tests of the existing cryptographic circuits
- do not refactor any code
