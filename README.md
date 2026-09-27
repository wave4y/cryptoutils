# CryptoUtils

Go 链式编码、摘要、加解密、签名与密钥派生工具，需要 **Go 1.22 或更高版本**。根包提供统一的公开 API；独立算法包也可直接使用。

## 安装

```sh
go get github.com/wave4y/cryptoutils
```

## 快速使用

```go
package main

import (
    "fmt"
    "log"

    "github.com/wave4y/cryptoutils"
)

func main() {
    result, err := cryptoutils.Init("abc").Sha256().Result()
    if err != nil {
        log.Fatal(err)
    }
    fmt.Println(string(result))
    // ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
}
```

链式调用保留首个错误，通过 `Result()` 获取结果与错误。摘要和 MAC 默认输出十六进制文本；加密、签名和密钥派生输出原始字节。完整约定与 AES-GCM 示例见 [使用指南](docs/usage.md)，旧模块路径与历史数据迁移见 [兼容性说明](docs/compatibility.md)。

## 功能索引

| 类别 | 功能与文档 |
| --- | --- |
| 摘要、认证与派生 | [SHA-2/3、SHAKE、Keccak、BLAKE2、SM3、HMAC、PBKDF2/HKDF、scrypt/Argon2id、bcrypt](docs/hash-kdf.md) |
| 对称加密 | [AES/SM4、ChaCha20-Poly1305、GCM/CCM、分组模式、XTS、CMAC/Poly1305、ZUC 及传统算法](docs/symmetric.md) |
| 公钥与密钥格式 | [RSA、ECDSA、Ed25519、ECDH/X25519、ElGamal、PEM/DER](docs/public-key.md) |
| RSA 数学与 CTF | [裸 RSA、大整数根、CRT、低指数/广播/共模、Fermat 与参数泄露](docs/rsa-ctf.md) |
| 国密协议 | [SM2 签名、加密、密钥交换](docs/sm2.md)；[SM9 身份签名、加密与 KEM](docs/sm9.md) |
| 后量子 | [ML-KEM、ML-DSA、SLH-DSA](docs/pqc.md) |

新业务优先使用认证加密；传统算法和裸模式的用途、格式及限制见各功能文档。部分实现尚不保证恒定时间，标准向量测试不等同于独立密码学审计或 FIPS 模块验证。参考源码在仓库内维护，来源、许可证和原有模块依赖见 [第三方说明](THIRD_PARTY.md)。

## 目录结构

```text
cryptoutils/
├── base.go / encoding.go / errors.go  # 链状态、编码与公共错误
├── symmetric.go / asymmetric.go      # 对称与传统公钥的公开适配
├── hash.go / kdf.go / password.go     # 摘要、派生与密码哈希的公开适配
├── *_api.go                          # 独立算法的根包适配
├── example_test.go                   # 可执行的 Go 文档示例
├── internal/
│   ├── symmetric/                    # 对称加密、模式、MAC 与填充
│   ├── asymmetric/                   # 传统公钥算法与 PEM/DER
│   ├── digest/                       # 摘要、HMAC 与 SHAKE
│   ├── derivation/                   # KDF、密码哈希与参数检查
│   └── idea/                         # IDEA 分组原语
├── sm2/ sm3/ sm4/ sm9/ zuc/          # 独立国密算法包
├── rsactf/                           # RSA 数学与 CTF 原语
├── pqc/                              # 后量子 API、内部原语与向量
├── utils/ rc4/                       # 历史兼容入口
├── tests/api/                        # 从使用者视角验证公开 API
└── docs/                             # 使用、兼容、架构与算法文档
```

算法单元测试留在对应包内，根包公开接口的回归测试集中在 `tests/api/`。测试文件不会编译进使用者程序。职责与依赖方向见 [架构说明](docs/architecture.md)，全部文档见 [文档导航](docs/README.md)。

## 测试

```sh
go test -coverpkg=./... ./...
go vet ./...
```

分层测试方式、覆盖率报告和向量位置见 [架构说明](docs/architecture.md#测试组织)。
