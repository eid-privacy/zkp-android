## Prerequisites

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


## Test

Run tests before building bindings

```sh
curl -L https://repo1.maven.org/maven2/net/java/dev/jna/jna/5.13.0/jna-5.13.0.jar -o jna-5.13.0.jar
export CLASSPATH=jna-5.13.0.jar
cargo test
```
