# Localized post-quantum algorithm cores

This directory is a **selective source adaptation of Cloudflare CIRCL v1.6.3**,
not an original implementation by cryptoutils and not a vendored copy of the
complete CIRCL module. The source is https://github.com/cloudflare/circl/tree/v1.6.3.
See [LICENSE](LICENSE) for the retained Cloudflare and Go Authors BSD licenses.

Only the dependency closure needed by ML-KEM-512/768/1024, ML-DSA-44/65/87 and
all twelve SLH-DSA parameter sets was copied: their algorithm implementations,
Kyber and Dilithium polynomial arithmetic, SHA-3/Keccak, serialization helpers,
and internal signature/KEM interfaces. The original architecture-specific
arithmetic/Keccak assembly and generic fallbacks are retained. No CIRCL module
entry, replace directive, network fetch or runtime dependency was added.
The existing x/crypto and x/sys versions remain sufficient.

`SOURCE_FILES.tsv` records each original source path and its upstream SHA-256.
Generated upstream .go files are kept as frozen source; their generators and
unrelated CIRCL algorithms are not included. The external-facing, length-checked
API is in `pqc/kem.go` and `pqc/signature.go`; these cores are Go internal packages.

Local modifications:

1. Import paths were relocated from github.com/cloudflare/circl to this directory.
2. SLH-DSA `readRandom` uses `io.ReadFull`, rejecting short entropy reads.
3. Each ML-DSA internal private key has a `Validate` method checking secret
   coefficient bounds, recomputed t0 and H(public key). Public `UnmarshalBinary`
   invokes it before imported keys are used by the high-level signing API.
4. Each ML-DSA `adapter.go` exposes an explicit 32-byte signing-randomness input
   inside this internal tree, allowing the outer API to propagate reader errors.
5. NIST ACVP sample tests exercise the ML-DSA internal FIPS interface alongside
   the cores; application APIs use the context-prefixed, pure signing interface.
6. Go files were formatted with gofmt and assembly trailing whitespace was removed. Other cryptographic arithmetic is unchanged.

Additional outer-API checks reject noncanonical ML-KEM expanded encodings,
validate SLH-DSA signatures against the public root stored in imported private
keys before returning them, bound contexts to 255 bytes and messages to 16 MiB,
and return errors for invalid parameters, lengths and entropy failures.

The samples test interoperability against published NIST expected outputs; they
are not a NIST algorithm-validation certificate or an independent security audit.
