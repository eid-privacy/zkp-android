TEST_VECTORS  := test-vectors/noir
ASSETS        := android/app/src/main/assets
MOPRO_VERSION := 0.3.4

CIRCUITS := \
	c03_holder_binding \
	c04_issuer_signature \
	c05_age_verification \
	c06_non_revocation \
	c09_full_proof \
	d10_swiyu_jwt

POCS          := zkp-pocs

JNA_VERSION   := 5.13.0
JNA_JAR       := jna-$(JNA_VERSION).jar
JNA_URL       := https://repo1.maven.org/maven2/net/java/dev/jna/jna/$(JNA_VERSION)/$(JNA_JAR)

CIRCUIT_SRS := $(foreach c,$(CIRCUITS),$(ASSETS)/noir_$(c).srs)
# Circuits whose JSON is also copied into the Android assets dir (d10 stays test-only).
ASSET_CIRCUITS := $(filter-out d10_swiyu_jwt,$(CIRCUITS))

.PHONY: setup download-srs circuits test

# ── Setup ───────────────────────────────────────────────────────────────────────
# Installs the SRS downloader and mopro-cli, then builds the native library.
setup:
	cargo install --git https://github.com/zkmopro/noir-rs --tag v1.0.0-beta.8 --features srs-downloader --bin srs_downloader
	cargo install mopro-cli --version $(MOPRO_VERSION) --locked
	mopro build --mode release --platforms android --architectures x86_64-linux-android aarch64-linux-android --no-auto-update

# ── Circuits ─────────────────────────────────────────────────────────────────────
# Builds the Noir circuits in the zkp-pocs submodule and copies their compiled
# JSON into the test vectors and Android assets.
circuits:
	git submodule update --init $(POCS)
	cd $(POCS) && devbox run circuits
	for c in $(CIRCUITS); do \
		cp $(POCS)/noir/$$c/target/$$c.json $(TEST_VECTORS)/noir_$$c.json; \
	done
	for c in $(ASSET_CIRCUITS); do \
		cp $(POCS)/noir/$$c/target/$$c.json $(ASSETS)/noir_$$c.json; \
	done

# ── Circuit SRS ────────────────────────────────────────────────────────────────
# Downloads the SRS from the committed circuit JSON when the JSON changes.
$(ASSETS)/noir_%.srs: $(TEST_VECTORS)/noir_%.json
	srs_downloader -c $< -o $(TEST_VECTORS)/noir_$*.srs
	cp $(TEST_VECTORS)/noir_$*.srs $@

download-srs: setup $(CIRCUIT_SRS)

# ── Test ─────────────────────────────────────────────────────────────────────────
# Runs the Rust tests with the JNA jar on the classpath (downloaded if missing).
$(JNA_JAR):
	curl -L $(JNA_URL) -o $@

test: $(JNA_JAR)
	CLASSPATH=$(JNA_JAR) cargo test
