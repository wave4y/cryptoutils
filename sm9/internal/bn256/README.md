# Local SM9 pairing implementation provenance

This directory contains a selected pure-Go subset of
https://github.com/emmansun/gmsm/tree/v0.29.8/sm9/bn256
(module checksum: h1:py9RwKHe4sIxjgD9mtWSIF5bmspP7IXvQ70Rx8x22Ow=).
It is local source code, not a module dependency. Upstream file SHA-256 hashes
before modifications are recorded in UPSTREAM_SHA256.txt.

Copyright (c) 2020 Sun Yimin (MIT) and portions Copyright (c) 2009 The Go Authors
(BSD-3-Clause). Complete notices are in LICENSE.MIT and LICENSE.BSD. Existing
source comments identifying earlier algorithm sources remain intact.

Selected runtime files: bn_pair.go, constants.go, curve.go, elliptic.go, g1.go,
g2.go, gfp.go, gfp_generic.go, gfp_invert_sqrt.go, gfp12.go, gfp12_exp_u.go,
gfp2.go, gfp2_sqrt.go, gfp2_g1_generic.go, gfp4.go, gt.go, params.go,
select_generic.go, twist.go.

Selected upstream tests: bn_pair_test.go and gfp_test.go, including fixed
pairing examples, a direct final-exponentiation comparison, bilinearity, and
base-field arithmetic. These tests are preserved under the same licenses.

Local changes:

- Removed build constraints from the three *_generic.go files so portable Go
  implementations are selected on every platform. No assembly or CPU probing
  dependency is included.
- Replaced internal/byteorder.BEUint64 with encoding/binary.BigEndian.Uint64.
- Removed unused gfp6Copy from select_generic.go, since the alternative 1-2-6-12
  extension tower is not included. The retained SM9 tower is 1-2-4-12.
- Fixed G1.Unmarshal and G1.UnmarshalCompressed to propagate coordinate-range
  decoding errors. The unmodified upstream version ignored these errors; the
  local regression tests reject the noncanonical (p,p) encoding of infinity.
- Replaced slice-to-array-pointer conversions in gfP.Marshal/Unmarshal with
  explicit buffers and length checks, avoiding a newer Go language construct.
- Added source-attribution headers and applied gofmt.

The protocol and input-validation layer lives two directories above. It uses
this repository's SM3 and SM4 and does not copy the upstream SM9 protocol API.
It rejects infinity points and checks subgroup membership before processing
externally supplied curve points; these checks are essential even though the
low-level group's decoder accepts the identity element for group arithmetic.
