# NIST ACVP samples

These gzip JSON files contain **selected original inputs and expected outputs**,
not outputs calculated by cryptoutils. They preserve each test group ID and test
case ID. The checked-in fixtures do not need the upstream source distribution,
network access, PowerShell, or any additional Go module at build/test time.
CIRCL's applicable license is retained in ../internal/reference/LICENSE.

## Reproducing the samples

Run the helper with PowerShell 7 from the repository root:

```powershell
pwsh -NoProfile -File ./pqc/testdata/extract_vectors.ps1
```

By default, the script runs `go env GOMODCACHE` and looks for the existing CIRCL
v1.6.3 source directory at `github.com/cloudflare/circl@v1.6.3` inside that cache.
To use an existing source checkout elsewhere, or run without Go installed, pass
its directory explicitly:

```powershell
pwsh -NoProfile -File ./pqc/testdata/extract_vectors.ps1 -Source 'D:/sources/circl-v1.6.3'
```

The script does not download source files or add a module dependency. It checks
that all required upstream inputs exist before replacing the three sample files,
and reports a clear error when Go or the source files cannot be found.

## Sample coverage

- ML-KEM: 9 cases, one key-generation, encapsulation, and decapsulation case for
  each of 512/768/1024. CIRCL's testdata README identifies NIST ACVP-Server commit
  f38183487eebff2952da0e5a3441371218acfe3f, under
  https://github.com/usnistgov/ACVP-Server/tree/f38183487eebff2952da0e5a3441371218acfe3f/gen-val/json-files/ML-KEM-keyGen-FIPS203
  and ML-KEM-encapDecap-FIPS203.
- ML-DSA: 15 cases for 44/65/87, from CIRCL's sign/mldsa/testdata. Includes key
  generation, deterministic/randomized internal signing, valid and invalid
  internal verification. The high-level context framing is tested separately.
- SLH-DSA: 48 cases for all twelve SHA2/SHAKE 128/192/256 s/f parameter sets:
  key generation, deterministic **external pure** signing, valid and invalid
  external verification. CIRCL's acvp_test.go identifies NIST ACVP-Server v1.1.0.38:
  https://github.com/usnistgov/ACVP-Server/tree/v1.1.0.38/gen-val/json-files

Fixtures intentionally sample the upstream suites to keep repository size and
test time manageable. Passing them is not an ACVP certification claim.
