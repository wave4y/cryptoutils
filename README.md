# CryptoUtils

Go 链式编码、摘要、加解密、签名与密钥派生工具。需要 **Go 1.22 或更高版本**。延续 `Init → SetKey/变换 → Result` 的接口约定；公私钥使用显式类型，密钥生成和多返回值操作使用独立函数。

本次扩展不新增第三方模块，也不升级原来的 `golang.org/x/crypto`。`go.mod` 中显式列出的 `x/sys` 是该原有版本已经依赖的间接模块；SM2、IDEA、CCM、CMAC、ZUC 等缺失部分在仓库内实现。

## 安装

```sh
go get github.com/wave4y/cryptoutils
```

导入根包：

```go
import "github.com/wave4y/cryptoutils"
```

从旧模块路径迁移时，请将项目中的 `import` 统一更新为 `github.com/wave4y/cryptoutils`；子包也使用该前缀，例如 `github.com/wave4y/cryptoutils/sm2`。随后运行 `go mod tidy` 更新依赖记录。函数与链式 API 的使用方式不变。

## 功能与文档

完整说明见 [文档导航](docs/README.md)。根包文件按编码、摘要、对称加密、公钥和算法适配命名；测试与对应功能同包放置，独立算法及其内部参考原语保留各自目录。

| 类别 | 已提供功能 | 详细 API |
| --- | --- | --- |
| 摘要 | SHA-2 全系列、SHA-3、SHAKE128/256、Keccak256/512、BLAKE2b/s、RIPEMD160、SM3、旧摘要 | [摘要与 KDF](docs/hash-kdf.md) |
| 认证加密 | AES/SM4-GCM、AES/SM4-CCM、ChaCha20-Poly1305、XChaCha20-Poly1305 | [对称加密](docs/symmetric.md) |
| 分组与流加密 | AES、SM4、DES/3DES、Blowfish、Twofish、TEA、XTEA、CAST5、IDEA；CBC/CTR/CFB/OFB/ECB/XTS；ZUC-128/256 | [对称加密](docs/symmetric.md) |
| 消息认证 | 通用 HMAC（包含 HMAC-SM3）、CMAC、Poly1305、ZUC MAC | [摘要与 KDF](docs/hash-kdf.md)、[对称加密](docs/symmetric.md) |
| 公钥 | RSA-OAEP/PSS、ECDSA、Ed25519、ECDH/X25519、ElGamal、PEM/DER | [公钥 API](docs/public-key.md) |
| 国密 SM2 | 身份绑定签名、C1C3C2/ASN.1 加密、带确认的密钥交换 | [SM2](docs/sm2.md) |
| SM9 | 身份签名/验签、身份密钥派生、KEM、XOR/SM4 加密 | [SM9](docs/sm9.md) |
| 后量子 | ML-KEM 512/768/1024、ML-DSA 44/65/87、SLH-DSA 全 12 个参数集 | [后量子 API](docs/pqc.md) |
| 派生与密码存储 | PBKDF2、HKDF、scrypt、Argon2id、bcrypt、PHC 格式与验证 | [摘要与 KDF](docs/hash-kdf.md) |

摘要/MAC 的便捷链式方法输出十六进制文本；加密、签名、密钥派生输出原始字节；验证成功保留原始消息，失败设置首个错误。使用文本协议时显式追加 `Base64Encode()` 或 `Hex()`。

新业务优先采用认证加密。旧算法及裸模式用于协议兼容/研究，具体格式和限制见各文档。SM2 的通用大整数实现、IDEA、ZUC 表查找实现尚不保证恒定时间；本次测试不等同于独立密码学审计。SM9 配对与后量子原语采用必要参考源码的本地适配，保留许可证；详见 [来源与维护说明](THIRD_PARTY.md)。

## 摘要与编码

```go
package main

import (
    "fmt"
    "log"

    "github.com/wave4y/cryptoutils"
)

func main() {
    p := cryptoutils.Init("abc").Sha256()
    result, err := p.Result()
    if err != nil {
        log.Fatal(err)
    }
    fmt.Println(string(result))
    // ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
}
```

- `Init` 接收 `string`、`[]byte` 或 `nil`，复制输入；其他类型可通过 `Err()` 检查错误。
- `Md4/Md5/Sha1/Sha224/Sha256/Sha384/Sha512/Sm3/Hash` 等固定摘要方法输出小写十六进制文本。`Hash("SHA-256")` 支持大小写和连字符写法。
- `HashBytes("sha256")` 输出原始摘要；例如 `Init("abc").HashBytes("sha256").Base64Encode()` 对原始摘要做 Base64，而 `Sha256().Base64Encode()` 对十六进制文本做 Base64。
- `Hex/HexDecode`、`Base64Encode/Base64Decode` 支持链式操作。解码失败不会返回部分结果。
- `String()` 和 `Bytes()` 不改变状态；`Bytes()`、`Result()` 返回副本。失败时分别返回空字符串或 nil，务必检查 `Err()`，或直接使用 `Result()`。
- 第一个错误会停止后续变换。`Reset()` 恢复原始输入、清除处理错误并保留密钥；非法输入类型的初始化错误不能被 Reset 清除。
- `SetKey` 复制密钥，不清除已有错误。对象是可变链，不支持多个 goroutine 同时操作同一个对象。

重复处理原始输入时显式重置：

```go
p := cryptoutils.Init("abc")
fmt.Println(p.Hex().String())                  // 616263
fmt.Println(p.Reset().Base64Encode().String()) // YWJj
```

## 推荐：AES-GCM

支持 16、24、32 字节 AES 密钥，自动生成 12 字节随机 nonce，并在解密时验证认证标签。输出是二进制 `nonce || ciphertext || tag`；需要传输文本时再做 Base64/Hex。

```go
package main

import (
    "crypto/rand"
    "fmt"
    "log"

    "github.com/wave4y/cryptoutils"
)

func main() {
    key := make([]byte, 32)
    if _, err := rand.Read(key); err != nil {
        log.Fatal(err)
    }
    // 实际项目应安全保存密钥，解密时使用同一密钥。
    aad := []byte("example:v1") // 可选附加认证数据，解密时必须一致
    encrypted, err := cryptoutils.EncryptAESGCM([]byte("hello"), key, aad)
    if err != nil {
        log.Fatal(err)
    }
    plaintext, err := cryptoutils.DecryptAESGCM(encrypted, key, aad)
    if err != nil {
        log.Fatal(err)
    }
    fmt.Println(string(plaintext)) // hello
}
```

同一密钥使用随机 nonce 加密时，不应超过 2^32 条消息。这里的 key 是二进制密钥，不是用户密码；密码存储应使用专用密码哈希算法。

链式接口为 `AESGCMEncrypt(aad)` / `AESGCMDecrypt(aad)`：

```go
p := cryptoutils.Init("hello")
p.SetKey(key)
encoded, err := p.AESGCMEncrypt(nil).Base64Encode().Result()
if err != nil {
    return err
}
d := cryptoutils.Init(encoded).Base64Decode()
d.SetKey(key)
plaintext, err := d.AESGCMDecrypt(nil).Result()
```

以上片段需放在返回 `error` 的函数内，并提供 `key`。

## HMAC 与填充

- `HMACSHA256(data, key)` 返回原始标签；`VerifyHMACSHA256(data, key, tag)` 用恒定时间比较验证标签。
- `Init(data).HMACSHA256(key)` 返回十六进制标签，遵循摘要链式接口的输出约定。
- `PKCS7Padding(data, blockSize)` / `PKCS7UnPadding(data, blockSize)` 返回 `([]byte, error)`，严格检查块大小、数据长度和全部填充字节，返回独立副本。AES 的块大小始终是 16，与密钥长度无关。
- `PKCS5Padding/PKCS5UnPadding` 是弃用的 8 字节块兼容接口。前者因旧签名不能返回 error，非法块大小返回 nil。以前把 AES 的 16 字节块传给 PKCS5Padding 的调用，应改用 PKCS7 两个接口。

## DES / RC4 与迁移

DES 的有效密钥长度不足以满足现代安全要求，RC4 也不适合安全用途。它们的兼容接口并不等同于 AES-GCM 的安全级别。

### DES 格式变化

`DesCBCEncrypt()` / `DesDecrypt()` 保留方法名与 8 字节密钥要求，但现在使用以下格式：

```text
"CU-DES\x01"（7 字节） || 随机 IV（8 字节） || CBC 密文 || HMAC-SHA256（32 字节）
```

认证覆盖版本前缀、IV 和密文；MAC 密钥用 HMAC-SHA256 从 DES key 和固定域 `cryptoutils/DES-CBC/HMAC-SHA256/v1` 派生。先认证后解密。这是本库的存储封装，不是通用 DES 协议格式，认证也不会提高 DES 密钥的抗穷举强度。

**新版密文不能被旧版库读取。** 旧版使用 `IV=key` 的裸密文只能显式调用 `DesDecryptLegacy()` 解密，新接口不自动降级。Legacy 没有认证能力，仅对来源可信的历史数据做离线迁移，然后用新密钥通过 AES-GCM 重新加密：

```go
old := cryptoutils.Init(oldCiphertext) // 如果原数据是 Hex/Base64，先解码
old.SetKey(oldKey)
plaintext, err := old.DesDecryptLegacy().Result()
if err != nil {
    return err
}
newCiphertext, err := cryptoutils.EncryptAESGCM(plaintext, newAESKey, nil)
```

### RC4 和随机字符串

`rc4` 目录保留原来的包名 `utils`，建议导入时使用别名：

```go
import legacyrc4 "github.com/wave4y/cryptoutils/rc4"
```

RC4 密文仍使用十六进制编码，仅供旧协议或 CTF。新增 `RC4Encrypt`、`RC4Decrypt`、`HexDecodeE` 和 `RandomStringE`，均返回 `(string, error)`；旧 `Rc4Encrypt`、`Rc4Decrypt`、`HexDecode`、`RandomString` 单值包装保留但标为弃用，失败时返回空字符串。`UrlEncode` 修正原来的 `UrlDncode` 拼写，旧名仍为别名。随机字符串已使用 `crypto/rand` 和无偏采样，不再修改全局伪随机数状态。

## 包结构

```text
cryptoutils/
├── *_api.go                 # SM2/SM9/ZUC/PQC 的根包链式适配
├── base.go / encoding.go    # 链状态、编码与错误处理
├── hash.go / mac.go         # 摘要与消息认证
├── aes_gcm.go / aead.go     # 认证加密
├── block_modes.go / ccm.go  # 分组模式与 CCM
├── des_legacy.go            # 旧 DES 封装与迁移接口
├── public_key.go / pem.go   # 传统公钥算法与密钥格式
├── kdf.go / password.go     # 派生与密码存储
├── *_test.go                # 按功能分组的测试、示例及互操作向量
├── sm2/ sm3/ sm4/ sm9/ zuc/ # 国密算法包
├── pqc/                    # 后量子 API、内部原语、测试向量
├── internal/idea/          # IDEA 分组原语
├── utils/ rc4/             # 兼容入口
└── docs/                   # 功能文档与导航
```

- 根包：共享链式接口、算法适配、显式参数校验、密码存储、密钥导入导出。
- `utils`：根包的类型别名和兼容包装，以及按 UTF-8 字节工作的 shell 转义辅助函数。
- `sm2`：SM2 曲线、公私钥、签名、加密及带确认的密钥交换。
- `sm3`：实现 `hash.Hash` 的 SM3。
- `sm4`：实现 `cipher.Block` 的 SM4 原语。它仅处理一个分组，不自行提供消息认证；非法缓冲区遵循 cipher.Block 合约触发 panic。
- `sm9`：身份签名、密钥封装及带完整性校验的加密。
- `pqc`：ML-KEM、ML-DSA、SLH-DSA；必要算法源码在包内维护。
- `zuc`：ZUC-128/256 流加密与 MAC。
- `internal/idea`：IDEA 分组原语。
- `rc4`：弃用的 RC4 和编码兼容辅助函数。

## 验证

```sh
go test ./... -cover
go vet ./...
```

测试调用正式公开接口，覆盖状态重置、错误传播、输入/输出隔离、AES-GCM 篡改和 AAD、DES 新格式与旧密文迁移、填充边界、HMAC 向量、SM3/SM4 标准向量和字节转义。原来仅测试测试文件内部实现的示例已替换为回归测试。

## 对照项目与参考来源

- [Go 标准库 crypto](https://pkg.go.dev/crypto) 和 [golang.org/x/crypto](https://pkg.go.dev/golang.org/x/crypto)：通用加密原语，以及 ChaCha20-Poly1305、Argon2、bcrypt 等扩展。
- [Tink Go](https://github.com/tink-crypto/tink-go)：面向业务的高层加密接口、密钥集和认证加密。
- [emmansun/gmsm](https://github.com/emmansun/gmsm)：国密 SM2、SM3、SM4 等实现。
- [deatil/go-cryptobin](https://github.com/deatil/go-cryptobin)：丰富算法和链式接口，适合研究、CTF 和协议兼容；需主动选择认证加密模式，不应直接依赖默认 ECB 模式保护业务数据。

使用这些项目时应根据各版本的 go.mod 检查 Go 版本要求。这里列出的是功能比较与实现研究的参考；本库没有新增这些项目的模块依赖，本地适配部分见上面的来源与维护说明。
