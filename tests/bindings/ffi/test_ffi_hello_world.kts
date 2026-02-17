import uniffi.mopro_example_app.*

var helloWorld = moproHelloWorld()
assert(helloWorld == "Hello, World!") { "Test string mismatch" }
