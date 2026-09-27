# 公钥、签名、密钥协商与 PEM/DER

这组接口使用显式的公钥/私钥参数，不把公钥对象放入链的 `SetKey([]byte)`。纯函数返回结果与 error；链式方法第一次失败后停止后续变换，`Result()` 返回错误。签名与加密结果都是原始字节，需要文本时再调用 `Hex()` 或 `Base64Encode()`。

## RSA

小模数、大指数、裸模幂及泄露参数题目使用独立的 [rsactf 数学接口](rsa-ctf.md)；下面的 OAEP/PSS 保持标准密钥和填充要求。

```go
privateKey, err := cryptoutils.GenerateRSAKey(2048)
ciphertext, err := cryptoutils.EncryptRSAOAEP(message, &privateKey.PublicKey, label)
plaintext, err := cryptoutils.DecryptRSAOAEP(ciphertext, privateKey, label)
signature, err := cryptoutils.SignRSAPSS(message, privateKey)
err = cryptoutils.VerifyRSAPSS(message, signature, &privateKey.PublicKey)
```

上述为接口片段，调用方需在每一步检查 err；变量 `message`、`label` 由调用方提供。

- `GenerateRSAKey(bits)` 创建 2048..8192 位、两个素数的 RSA 私钥。输入密钥也采用这个范围，并检查公私钥字段、指数和两素数关系；私钥的 p/q 分别通过 `ProbablyPrime(32)` 概率素性检查，合数因子在导入、导出和私钥操作入口统一拒绝。
- OAEP 的摘要和 MGF1 均使用 SHA-256；`label` 可为 nil，加解密必须一致，最多 1 MiB。最大明文长度是 `modulusBytes - 66`，即 2048 位 RSA 为 190 字节。密文是固定 `modulusBytes` 字节，不做分段大文件加密。
- PSS 对输入消息计算 SHA-256，固定使用 32 字节随机 salt；验证同样要求 32 字节 salt。输入是消息，不是提前计算的 digest。
- 私钥操作重建本地 CRT 缓存，避免调用方过期或损坏的 `Precomputed` 字段触发异常，也不修改传入密钥。

链式方法：`RSAOAEPEncrypt(publicKey, label)`、`RSAOAEPDecrypt(privateKey, label)`、`RSAPSSSign(privateKey)`、`RSAPSSVerify(publicKey, signature)`。验证成功保留当前消息；失败变为 sticky error。

## ECDSA 与 Ed25519

| 操作 | 接口 |
| --- | --- |
| 创建 ECDSA 私钥 | `GenerateECDSAKey(curveName)` |
| 签名/验证 ECDSA | `SignECDSA(message, privateKey)` / `VerifyECDSA(message, signature, publicKey)` |
| 创建 Ed25519 密钥 | `GenerateEd25519Key()`，返回 public、private、error |
| 签名/验证 Ed25519 | `SignEd25519(message, privateKey)` / `VerifyEd25519(message, signature, publicKey)` |

ECDSA 支持 `P256`、`P384`、`P521`，也接受 `P-256` 等写法和 `secp256r1` 等对应名称；分别使用 SHA-256、SHA-384、SHA-512。签名编码为 ASN.1 DER 的 `(r,s)`，不是固定宽度的 `r || s`。只接受对应的标准库曲线对象，拒绝自定义曲线、曲线外点、无效私钥标量和公私钥不匹配。

Ed25519 实现标准的直接消息签名，不采用 Ed25519ph 或 context 模式。私钥是标准库的 64 字节形式；32 字节 seed 可先通过标准库 `ed25519.NewKeyFromSeed` 转换。签名前会检查私钥的 seed 与 public 部分是否一致。

链式方法为 `ECDSASign(privateKey)`、`ECDSAVerify(publicKey, signature)`、`Ed25519Sign(privateKey)`、`Ed25519Verify(publicKey, signature)`。所有验证函数成功返回 nil，失败返回 error；链式验证成功保留消息。

签名与验证消息限制为 `MaxPublicKeyMessage`（16 MiB）。密钥结构或长度错误可用 `errors.Is(err, ErrInvalidAsymmetricKey)` 判断；无效签名可用 `errors.Is(err, ErrSignatureVerification)` 判断。

## ECDH / X25519

```go
privateKey, publicKey, err := cryptoutils.GenerateECDHKey("X25519")
shared, err := cryptoutils.ECDH(privateKey, peerPublicKey)
derived, err := cryptoutils.Init(shared).HKDF(salt, contextInfo, nil).Result()
```

`GenerateECDHKey` 支持 P256、P384、P521、X25519，返回 private、public、error。`ECDH` 返回原始共享秘密，拒绝不匹配曲线、无效密钥和导致全零秘密的 X25519 低阶公钥。

`Init(nil).ECDH(privateKey, peerPublicKey)` 是链式适配：当前输入不参与计算，输出替换为共享秘密。应用应使用 HKDF 从秘密派生用途明确的密钥，并在协议中认证对方公钥；单独使用 ECDH 不提供对方身份认证。

## ElGamal 兼容接口

```go
privateKey, err := cryptoutils.GenerateElGamalKey()
ciphertext, err := cryptoutils.EncryptElGamal(message, &privateKey.PublicKey)
plaintext, err := cryptoutils.DecryptElGamal(ciphertext, privateKey)
```

`ElGamalPublicKey` / `ElGamalPrivateKey` 是原有 `x/crypto/openpgp/elgamal` 类型的别名。生成与导入的参数仅允许 [RFC 3526 第 3 节](https://www.rfc-editor.org/rfc/rfc3526.html#section-3) 的 2048 位安全素数组、g=2；检查公钥所属子群和私钥范围。

加密复用已有依赖的 OpenPGP 风格 PKCS#1 v1.5 填充，最大明文 245 字节；输出是本库定义的 `c1 || c2`，每部分固定 256 字节，总计 512 字节。它不是完整 OpenPGP 报文。链式接口为 `ElGamalEncrypt(publicKey)` / `ElGamalDecrypt(privateKey)`。

这些接口标为 Deprecated，仅用于旧协议研究、历史数据和 CTF。底层 ElGamal 不提供认证，也不保证恒定时间；向不可信调用者暴露其填充错误会形成解密 oracle。新业务应使用现有 RSA-OAEP 或合适的认证加密协议。标准库的 PKCS#8/PKIX 不支持这里的 ElGamal 密钥，因此下面的 PEM/DER 函数不导入、导出 ElGamal。

## PEM 与 DER

| 函数 | 格式 |
| --- | --- |
| `MarshalPrivateKeyDER(key)` | 未加密 PKCS#8 |
| `MarshalPublicKeyDER(key)` | PKIX SubjectPublicKeyInfo |
| `MarshalPrivateKeyPEM(key)` | `PRIVATE KEY` PEM |
| `MarshalPublicKeyPEM(key)` | `PUBLIC KEY` PEM |
| `ParsePrivateKeyDER(data)` | PKCS#8、RSA PKCS#1、EC SEC1 |
| `ParsePublicKeyDER(data)` | PKIX、RSA PKCS#1 |
| `ParsePrivateKeyPEM(data)` | `PRIVATE KEY`、`RSA PRIVATE KEY`、`EC PRIVATE KEY` |
| `ParsePublicKeyPEM(data)` | `PUBLIC KEY`、`RSA PUBLIC KEY` |

支持 RSA、ECDSA、Ed25519 和标准库 ECDH 密钥。`Parse...` 通用函数返回 `crypto.PrivateKey` / `crypto.PublicKey`，需要时由调用方做类型断言。导入后仍执行前面的密钥类型、长度和数学关系检查。

NIST 曲线的 ECDSA/ECDH 使用相同的标准编码，所以标准库通用解析会返回 ECDSA 类型。若确定需要 ECDH，可以直接用 `ParseECDHPrivateKeyDER`、`ParseECDHPublicKeyDER`、`ParseECDHPrivateKeyPEM`、`ParseECDHPublicKeyPEM`，它们负责转换，返回 `*ecdh.PrivateKey` / `*ecdh.PublicKey`。X25519 不需要这种转换。

DER 输入最多 64 KiB，PEM 最多 128 KiB；拒绝尾随 DER 数据、多 PEM 块、PEM 之外的非空白内容和带加密 headers 的 PEM。RSA 整数范围会在标准库解析器进行 CRT 计算前检查。这里只导出明文私钥，调用方应自行选择安全的存储位置与访问权限；不支持密码加密 PEM、证书或密钥容器格式的自动转换。
