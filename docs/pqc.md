# 后量子算法

本库实现 FIPS 203 ML-KEM、FIPS 204 ML-DSA 和 FIPS 205 SLH-DSA 的全部标准参数组。
算法核心是 **CIRCL v1.6.3 相关源码的本地化适配**，保存在 `pqc/internal/reference`，
并非全新原创算法实现，也没有在 go.mod 中添加 CIRCL 或其他 module。来源、原文件
SHA-256、许可证和修改说明见 [reference/README](../pqc/internal/reference/README.md)。

## ML-KEM：建立共享密钥

| 参数常量 | 公钥字节 | 私钥字节 | 密文字节 | 共享秘密字节 |
|---|---:|---:|---:|---:|
| MLKEM512 | 800 | 1632 | 768 | 32 |
| MLKEM768 | 1184 | 2400 | 1088 | 32 |
| MLKEM1024 | 1568 | 3168 | 1568 | 32 |

```go
import crypto "www.gitlablow.com/wave4y/cryptoutils"

publicKey, privateKey, err := crypto.GenerateMLKEMKey(crypto.MLKEM768)
if err != nil { return err }
ciphertext, senderSecret, err := crypto.EncapsulateMLKEM(publicKey)
if err != nil { return err }
receiverSecret, err := crypto.DecapsulateMLKEM(ciphertext, privateKey)
if err != nil { return err }
// senderSecret 与 receiverSecret 相同；在协议中结合上下文和KDF派生所需密钥。
```

ML-KEM 是密钥封装，不直接加密业务数据，也不认证通信对端。双方应通过经过认证的
协议使用共享秘密。按 FIPS 203 的隐式拒绝规则，同长度密文被篡改时解封装仍返回
32 字节秘密，该秘密与发送端不同；不能把 `err == nil` 当成完整性验证。长度错误
会返回错误。认证加密或协议级密钥确认负责检测错误的共享秘密。

密钥是强类型 `*MLKEMPublicKey` / `*MLKEMPrivateKey`；`Bytes()` 返回独立副本，
`Parameter()` 返回参数组。持久化时同时保存参数组，使用
`ParseMLKEMPublicKey(parameter, encoded)` / `ParseMLKEMPrivateKey(parameter, encoded)`
恢复。解析拒绝错误长度、非规范系数和不一致的内嵌公钥哈希。空指针/零值密钥返回错误。

## ML-DSA 与 SLH-DSA：数字签名

| 参数常量 | 公钥字节 | 私钥字节 | 签名字节 |
|---|---:|---:|---:|
| MLDSA44 | 1312 | 2560 | 2420 |
| MLDSA65 | 1952 | 4032 | 3309 |
| MLDSA87 | 2592 | 4896 | 4627 |
| SLHDSASHA2128s / SLHDSASHAKE128s | 32 | 64 | 7856 |
| SLHDSASHA2128f / SLHDSASHAKE128f | 32 | 64 | 17088 |
| SLHDSASHA2192s / SLHDSASHAKE192s | 48 | 96 | 16224 |
| SLHDSASHA2192f / SLHDSASHAKE192f | 48 | 96 | 35664 |
| SLHDSASHA2256s / SLHDSASHAKE256s | 64 | 128 | 29792 |
| SLHDSASHA2256f / SLHDSASHAKE256f | 64 | 128 | 49856 |

`s` 参数组优先缩小签名，`f` 参数组优先签名速度。公钥、私钥和签名均为标准原始
字节编码；参数组必须单独保存，不能单靠长度区分 SHA2/SHAKE 或 s/f。

```go
publicKey, privateKey, err := crypto.GenerateMLDSAKey(crypto.MLDSA65)
if err != nil { return err }
message := []byte("需要签名的数据")
context := []byte("my-app/v1")
signature, err := crypto.Init(message).
    MLDSASign(crypto.MLDSA65, privateKey, context).Result()
if err != nil { return err }

checked := crypto.Init(message).
    MLDSAVerify(crypto.MLDSA65, publicKey, signature, context)
if err := checked.Err(); err != nil { return err }
// checked.Bytes() 仍为原 message。
```

SLH-DSA 使用 `GenerateSLHDSAKey`、`SLHDSASign`、`SLHDSAVerify`，例如选择
`SLHDSASHAKE128f`。统一入口为 `GeneratePQSignatureKey`、`PQSign`、`PQVerify`。

纯函数形式为：

- `SignMLDSA(parameter, data, privateKey, context)` / `VerifyMLDSA(parameter, data, publicKey, signature, context)`。
- `SignSLHDSA(...)` / `VerifySLHDSA(...)`，参数顺序相同。
- `SignPQ(...)` / `VerifyPQ(...)` 接受任意支持的签名参数组。

签名链输出原始签名字节，可再接 `.Hex()` 或 `.Base64Encode()`。验签成功保留原数据，
失败设置 sticky error 并清空结果；后续变换停止，调用 `Reset()` 才能恢复。
签名函数使用标准 **pure** 接口，包含 `0x00 || context长度 || context || message`
域分隔；不会隐式对消息预哈希。context 最多 255 字节，nil 与空 context 等价。
消息限制为 16 MiB。根包签名默认使用 crypto/rand 的随机化签名。

## 高级用法与输入检查

`pqc` 子包提供可传入 `io.Reader` 的密钥生成、封装和签名接口；nil reader 选择
`crypto/rand.Reader`，短读与随机源错误返回 error，不产生部分结果。

- `pqc.DeriveMLKEM(parameter, seed)` 接受 64 字节秘密种子 `d || z`。
- `pqc.DeriveSignatureKey(parameter, seed)`：ML-DSA 接受 32 字节秘密种子；SLH-DSA
  接受 `SK.seed || SK.prf || PK.seed`，长度为 48/72/96 字节。
- `pqc.SignDeterministic(parameter, privateKey, message, context)` 提供标准可选的
  确定性签名模式，便于协议对接和向量验证。
- `pqc.Sign(parameter, privateKey, message, context, random)` 与 `pqc.Verify(parameter,
  publicKey, message, signature, context)` 注意与根包的参数顺序区别。

派生种子必须由安全随机源产生并作为秘密保管。导入 ML-DSA 私钥时检查秘密系数范围、
重算 t0 和公钥哈希；SLH-DSA 返回签名前校验签名与私钥内的公钥根一致，拒绝损坏的
私钥。错误可以用 `errors.Is` 匹配 `pqc.ErrParameter`、`ErrKey`、`ErrSeed`、
`ErrContext`、`ErrMessageTooLarge`、`ErrVerification`；随机源错误保留原始 error。

## 验证与标准

仓库保存了 72 条 NIST ACVP 原始样本，覆盖所有参数组的标准密钥编码、封装/解封装、
签名、正确/错误验签。期望值来自 NIST 数据，不由本库生成。ML-DSA 样本验证标准的
内部签名接口，公开的 context 分隔接口另有往返、篡改和错误输入测试；SLH-DSA 样本
直接对照外部 pure 签名接口。另有随机源失败/短读、非法长度、非规范系数、畸形私钥
和 ML-KEM 隐式拒绝的回归测试。测试样本说明见 [testdata](../pqc/testdata/README.md)。

```sh
go test ./pqc/... ./...
go test -tags purego ./pqc/...
```

通过样本对照不代表获得 NIST 验证证书。实现依据：
[FIPS 203](https://doi.org/10.6028/NIST.FIPS.203)、
[FIPS 204](https://doi.org/10.6028/NIST.FIPS.204)、
[FIPS 205](https://doi.org/10.6028/NIST.FIPS.205)。
