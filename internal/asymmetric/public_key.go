package asymmetric

import (
	"crypto"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"errors"
	"fmt"
	"math/big"
	"strings"

	"golang.org/x/crypto/openpgp/elgamal"
)

var (
	ErrInvalidAsymmetricKey  = errors.New("cryptoutils: invalid asymmetric key")
	ErrSignatureVerification = errors.New("cryptoutils: signature verification failed")
)

// MaxPublicKeyMessage bounds a single signing or verification input.
const MaxPublicKeyMessage = 16 << 20

func checkPublicKeyMessage(message []byte) error {
	if len(message) > MaxPublicKeyMessage {
		return fmt.Errorf("cryptoutils: public-key message exceeds %d bytes", MaxPublicKeyMessage)
	}
	return nil
}

// GenerateRSAKey creates a two-prime RSA key of 2048..8192 bits.
func GenerateRSAKey(bits int) (*rsa.PrivateKey, error) {
	if bits < 2048 || bits > 8192 {
		return nil, fmt.Errorf("cryptoutils: RSA bits must be 2048..8192")
	}
	return rsa.GenerateKey(rand.Reader, bits)
}

func checkedRSAPublic(key *rsa.PublicKey) (*rsa.PublicKey, error) {
	if key == nil || key.N == nil || key.N.Sign() <= 0 || key.N.BitLen() < 2048 || key.N.BitLen() > 8192 || key.N.Bit(0) == 0 || key.E < 3 || key.E > 1<<31-1 || key.E&1 == 0 {
		return nil, ErrInvalidAsymmetricKey
	}
	return &rsa.PublicKey{N: new(big.Int).Set(key.N), E: key.E}, nil
}

func checkedRSAPrivate(key *rsa.PrivateKey) (*rsa.PrivateKey, error) {
	if key == nil {
		return nil, ErrInvalidAsymmetricKey
	}
	public, err := checkedRSAPublic(&key.PublicKey)
	if err != nil {
		return nil, err
	}
	if key.D == nil || key.D.Sign() <= 0 || key.D.Cmp(key.N) >= 0 || len(key.Primes) != 2 {
		return nil, ErrInvalidAsymmetricKey
	}
	copyKey := &rsa.PrivateKey{PublicKey: *public, D: new(big.Int).Set(key.D), Primes: make([]*big.Int, 2)}
	for i, prime := range key.Primes {
		if prime == nil || prime.Cmp(big.NewInt(2)) <= 0 || prime.BitLen() > key.N.BitLen() || prime.Bit(0) == 0 {
			return nil, ErrInvalidAsymmetricKey
		}
		copyKey.Primes[i] = new(big.Int).Set(prime)
	}
	if copyKey.Primes[0].Cmp(copyKey.Primes[1]) == 0 {
		return nil, ErrInvalidAsymmetricKey
	}
	if new(big.Int).GCD(nil, nil, copyKey.Primes[0], copyKey.Primes[1]).Cmp(big.NewInt(1)) != 0 {
		return nil, ErrInvalidAsymmetricKey
	}
	if err := copyKey.Validate(); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidAsymmetricKey, err)
	}
	// Never trust or mutate caller-provided CRT caches, which may be stale or nil.
	copyKey.Precompute()
	return copyKey, nil
}

// EncryptRSAOAEP encrypts a short message using SHA-256 for OAEP and MGF1.
// The label must match during decryption. Maximum input is modulusBytes - 66.
func EncryptRSAOAEP(plaintext []byte, key *rsa.PublicKey, label []byte) ([]byte, error) {
	public, err := checkedRSAPublic(key)
	if err != nil {
		return nil, err
	}
	if len(label) > 1<<20 {
		return nil, fmt.Errorf("cryptoutils: OAEP label exceeds 1 MiB")
	}
	return rsa.EncryptOAEP(sha256.New(), rand.Reader, public, plaintext, label)
}

func DecryptRSAOAEP(ciphertext []byte, key *rsa.PrivateKey, label []byte) ([]byte, error) {
	private, err := checkedRSAPrivate(key)
	if err != nil {
		return nil, err
	}
	if len(label) > 1<<20 || len(ciphertext) != private.Size() {
		return nil, rsa.ErrDecryption
	}
	return rsa.DecryptOAEP(sha256.New(), rand.Reader, private, ciphertext, label)
}

// SignRSAPSS hashes a message with SHA-256 and signs using a 32-byte PSS salt.
func SignRSAPSS(message []byte, key *rsa.PrivateKey) ([]byte, error) {
	if err := checkPublicKeyMessage(message); err != nil {
		return nil, err
	}
	private, err := checkedRSAPrivate(key)
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256(message)
	return rsa.SignPSS(rand.Reader, private, crypto.SHA256, digest[:], &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash})
}

func VerifyRSAPSS(message, signature []byte, key *rsa.PublicKey) error {
	if err := checkPublicKeyMessage(message); err != nil {
		return err
	}
	public, err := checkedRSAPublic(key)
	if err != nil {
		return err
	}
	if len(signature) != public.Size() {
		return ErrSignatureVerification
	}
	digest := sha256.Sum256(message)
	if err := rsa.VerifyPSS(public, crypto.SHA256, digest[:], signature, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash}); err != nil {
		return ErrSignatureVerification
	}
	return nil
}

func namedSigningCurve(name string) (elliptic.Curve, error) {
	switch strings.NewReplacer("-", "", "_", "").Replace(strings.ToLower(strings.TrimSpace(name))) {
	case "p256", "secp256r1":
		return elliptic.P256(), nil
	case "p384", "secp384r1":
		return elliptic.P384(), nil
	case "p521", "secp521r1":
		return elliptic.P521(), nil
	default:
		return nil, fmt.Errorf("cryptoutils: unsupported curve %q", name)
	}
}

func allowedSigningCurve(curve elliptic.Curve) bool {
	return curve == elliptic.P256() || curve == elliptic.P384() || curve == elliptic.P521()
}

func GenerateECDSAKey(curve string) (*ecdsa.PrivateKey, error) {
	c, err := namedSigningCurve(curve)
	if err != nil {
		return nil, err
	}
	return ecdsa.GenerateKey(c, rand.Reader)
}

func checkedECDSAPublic(key *ecdsa.PublicKey) (*ecdsa.PublicKey, error) {
	if key == nil || !allowedSigningCurve(key.Curve) || key.X == nil || key.Y == nil || key.X.Sign() < 0 || key.Y.Sign() < 0 {
		return nil, ErrInvalidAsymmetricKey
	}
	if key.X.BitLen() > key.Curve.Params().BitSize || key.Y.BitLen() > key.Curve.Params().BitSize || !key.Curve.IsOnCurve(key.X, key.Y) {
		return nil, ErrInvalidAsymmetricKey
	}
	return &ecdsa.PublicKey{Curve: key.Curve, X: new(big.Int).Set(key.X), Y: new(big.Int).Set(key.Y)}, nil
}

func checkedECDSAPrivate(key *ecdsa.PrivateKey) (*ecdsa.PrivateKey, error) {
	if key == nil {
		return nil, ErrInvalidAsymmetricKey
	}
	public, err := checkedECDSAPublic(&key.PublicKey)
	if err != nil {
		return nil, err
	}
	if key.D == nil || key.D.Sign() <= 0 || key.D.Cmp(key.Curve.Params().N) >= 0 {
		return nil, ErrInvalidAsymmetricKey
	}
	x, y := key.Curve.ScalarBaseMult(key.D.Bytes())
	if x.Cmp(key.X) != 0 || y.Cmp(key.Y) != 0 {
		return nil, ErrInvalidAsymmetricKey
	}
	return &ecdsa.PrivateKey{PublicKey: *public, D: new(big.Int).Set(key.D)}, nil
}

func ecdsaMessageDigest(message []byte, curve elliptic.Curve) []byte {
	switch curve {
	case elliptic.P256():
		sum := sha256.Sum256(message)
		return sum[:]
	case elliptic.P384():
		sum := sha512.Sum384(message)
		return sum[:]
	default:
		sum := sha512.Sum512(message)
		return sum[:]
	}
}

// SignECDSA returns an ASN.1 DER (r,s) signature. P-256/P-384/P-521 use
// SHA-256/SHA-384/SHA-512 respectively; the input is a message, not a digest.
func SignECDSA(message []byte, key *ecdsa.PrivateKey) ([]byte, error) {
	if err := checkPublicKeyMessage(message); err != nil {
		return nil, err
	}
	private, err := checkedECDSAPrivate(key)
	if err != nil {
		return nil, err
	}
	return ecdsa.SignASN1(rand.Reader, private, ecdsaMessageDigest(message, private.Curve))
}

func VerifyECDSA(message, signature []byte, key *ecdsa.PublicKey) error {
	if err := checkPublicKeyMessage(message); err != nil {
		return err
	}
	public, err := checkedECDSAPublic(key)
	if err != nil {
		return err
	}
	if len(signature) == 0 || len(signature) > 144 || !ecdsa.VerifyASN1(public, ecdsaMessageDigest(message, public.Curve), signature) {
		return ErrSignatureVerification
	}
	return nil
}

func GenerateEd25519Key() (ed25519.PublicKey, ed25519.PrivateKey, error) {
	return ed25519.GenerateKey(rand.Reader)
}

func checkedEd25519Private(key ed25519.PrivateKey) (ed25519.PrivateKey, error) {
	if len(key) != ed25519.PrivateKeySize {
		return nil, ErrInvalidAsymmetricKey
	}
	private := ed25519.NewKeyFromSeed(key[:ed25519.SeedSize])
	if subtle.ConstantTimeCompare(private, key) != 1 {
		return nil, ErrInvalidAsymmetricKey
	}
	return private, nil
}

func SignEd25519(message []byte, key ed25519.PrivateKey) ([]byte, error) {
	if err := checkPublicKeyMessage(message); err != nil {
		return nil, err
	}
	private, err := checkedEd25519Private(key)
	if err != nil {
		return nil, err
	}
	return ed25519.Sign(private, message), nil
}

func VerifyEd25519(message, signature []byte, key ed25519.PublicKey) error {
	if err := checkPublicKeyMessage(message); err != nil {
		return err
	}
	if len(key) != ed25519.PublicKeySize {
		return ErrInvalidAsymmetricKey
	}
	if len(signature) != ed25519.SignatureSize || !ed25519.Verify(key, message, signature) {
		return ErrSignatureVerification
	}
	return nil
}

func namedECDHCurve(name string) (ecdh.Curve, error) {
	switch strings.NewReplacer("-", "", "_", "").Replace(strings.ToLower(strings.TrimSpace(name))) {
	case "p256", "secp256r1":
		return ecdh.P256(), nil
	case "p384", "secp384r1":
		return ecdh.P384(), nil
	case "p521", "secp521r1":
		return ecdh.P521(), nil
	case "x25519":
		return ecdh.X25519(), nil
	default:
		return nil, fmt.Errorf("cryptoutils: unsupported ECDH curve %q", name)
	}
}

func allowedECDHCurve(curve ecdh.Curve) bool {
	return curve == ecdh.P256() || curve == ecdh.P384() || curve == ecdh.P521() || curve == ecdh.X25519()
}

// GenerateECDHKey returns a private/public key pair for P256/P384/P521/X25519.
func GenerateECDHKey(curve string) (*ecdh.PrivateKey, *ecdh.PublicKey, error) {
	c, err := namedECDHCurve(curve)
	if err != nil {
		return nil, nil, err
	}
	private, err := c.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	return private, private.PublicKey(), nil
}

func checkedECDHPrivate(key *ecdh.PrivateKey) (*ecdh.PrivateKey, error) {
	if key == nil || !allowedECDHCurve(key.Curve()) {
		return nil, ErrInvalidAsymmetricKey
	}
	copyKey, err := key.Curve().NewPrivateKey(key.Bytes())
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidAsymmetricKey, err)
	}
	return copyKey, nil
}

func checkedECDHPublic(key *ecdh.PublicKey) (*ecdh.PublicKey, error) {
	if key == nil || !allowedECDHCurve(key.Curve()) {
		return nil, ErrInvalidAsymmetricKey
	}
	copyKey, err := key.Curve().NewPublicKey(key.Bytes())
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidAsymmetricKey, err)
	}
	return copyKey, nil
}

// ECDH returns a raw shared secret. Derive application keys with HKDF and bind
// the authenticated protocol context; bare ECDH does not authenticate a peer.
func ECDH(privateKey *ecdh.PrivateKey, publicKey *ecdh.PublicKey) ([]byte, error) {
	private, err := checkedECDHPrivate(privateKey)
	if err != nil {
		return nil, err
	}
	public, err := checkedECDHPublic(publicKey)
	if err != nil {
		return nil, err
	}
	return private.ECDH(public)
}

// ElGamalPublicKey and ElGamalPrivateKey retain the upstream legacy key format.
type ElGamalPublicKey = elgamal.PublicKey
type ElGamalPrivateKey = elgamal.PrivateKey

// RFC 3526 section 3, group 14. Only this fixed safe-prime group is accepted.
const elGamalPrimeHex = "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF"

func elGamalGroup() (p, q *big.Int) {
	p, _ = new(big.Int).SetString(elGamalPrimeHex, 16)
	q = new(big.Int).Rsh(new(big.Int).Sub(p, big.NewInt(1)), 1)
	return
}

// GenerateElGamalKey creates a key in the fixed 2048-bit group.
// Deprecated: legacy/CTF only; this primitive is unauthenticated and not constant time.
func GenerateElGamalKey() (*ElGamalPrivateKey, error) {
	p, q := elGamalGroup()
	x, err := rand.Int(rand.Reader, new(big.Int).Sub(q, big.NewInt(2)))
	if err != nil {
		return nil, err
	}
	x.Add(x, big.NewInt(2))
	g := big.NewInt(2)
	y := new(big.Int).Exp(g, x, p)
	return &ElGamalPrivateKey{PublicKey: ElGamalPublicKey{P: p, G: g, Y: y}, X: x}, nil
}

func checkElGamalPublic(key *ElGamalPublicKey) error {
	if key == nil || key.P == nil || key.G == nil || key.Y == nil {
		return ErrInvalidAsymmetricKey
	}
	p, q := elGamalGroup()
	if key.P.Cmp(p) != 0 || key.G.Cmp(big.NewInt(2)) != 0 || key.Y.Cmp(big.NewInt(1)) <= 0 || key.Y.Cmp(new(big.Int).Sub(p, big.NewInt(1))) >= 0 {
		return ErrInvalidAsymmetricKey
	}
	if new(big.Int).Exp(key.Y, q, p).Cmp(big.NewInt(1)) != 0 {
		return ErrInvalidAsymmetricKey
	}
	return nil
}

// EncryptElGamal uses the upstream OpenPGP-style PKCS#1 v1.5 padding and returns
// fixed-width c1 || c2 (256 bytes each). This is not an OpenPGP packet.
// Deprecated: legacy/CTF only; this encryption does not authenticate ciphertext.
func EncryptElGamal(plaintext []byte, key *ElGamalPublicKey) ([]byte, error) {
	if err := checkElGamalPublic(key); err != nil {
		return nil, err
	}
	for attempts := 0; attempts < 16; attempts++ {
		c1, c2, err := elgamal.Encrypt(rand.Reader, key, plaintext)
		if err != nil {
			return nil, err
		}
		if c1.Cmp(big.NewInt(1)) <= 0 {
			continue
		}
		out := make([]byte, 512)
		c1.FillBytes(out[:256])
		c2.FillBytes(out[256:])
		return out, nil
	}
	return nil, fmt.Errorf("cryptoutils: ElGamal could not generate an ephemeral key")
}

// DecryptElGamal accepts fixed-width c1 || c2. Do not expose its padding errors
// to untrusted clients: legacy ElGamal is vulnerable to chosen-ciphertext attacks.
// Deprecated: legacy/CTF only.
func DecryptElGamal(ciphertext []byte, key *ElGamalPrivateKey) ([]byte, error) {
	if key == nil {
		return nil, ErrInvalidAsymmetricKey
	}
	if err := checkElGamalPublic(&key.PublicKey); err != nil {
		return nil, err
	}
	p, q := elGamalGroup()
	if key.X == nil || key.X.Cmp(big.NewInt(2)) < 0 || key.X.Cmp(q) >= 0 || new(big.Int).Exp(key.G, key.X, p).Cmp(key.Y) != 0 {
		return nil, ErrInvalidAsymmetricKey
	}
	if len(ciphertext) != 512 {
		return nil, fmt.Errorf("cryptoutils: invalid ElGamal ciphertext length")
	}
	c1, c2 := new(big.Int).SetBytes(ciphertext[:256]), new(big.Int).SetBytes(ciphertext[256:])
	if c1.Cmp(big.NewInt(1)) <= 0 || c1.Cmp(p) >= 0 || c2.Sign() <= 0 || c2.Cmp(p) >= 0 || new(big.Int).Exp(c1, q, p).Cmp(big.NewInt(1)) != 0 {
		return nil, fmt.Errorf("cryptoutils: invalid ElGamal ciphertext")
	}
	return elgamal.Decrypt(key, c1, c2)
}
