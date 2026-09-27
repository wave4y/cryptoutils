# NIST ACVP samples

These gzip JSON files contain **selected original inputs and expected outputs**,
not outputs calculated by cryptoutils. They preserve each test group ID and test
case ID. `extract_vectors.ps1 -Source <path-to-circl-v1.6.3>` reproduces the files
from the CIRCL v1.6.3 source distribution. The checked-in fixtures do not need that
source distribution, network access, PowerShell, or any additional Go module at
build/test time. CIRCL's applicable license is retained in ../internal/reference/LICENSE.

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
