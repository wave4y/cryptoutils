# 文档导航

从[项目说明](../README.md)了解安装方式、链式 API 和错误处理，再按所需功能查阅：

| 文档 | 内容 |
| --- | --- |
| [摘要、HMAC、密钥派生和密码哈希](hash-kdf.md) | 摘要算法、SHAKE、通用 HMAC、PBKDF2、HKDF、scrypt、Argon2id、bcrypt |
| [对称加密、模式与 MAC](symmetric.md) | AEAD、分组模式、CCM、XTS、CMAC、Poly1305、ZUC |
| [公钥、签名、密钥协商与 PEM/DER](public-key.md) | RSA、ECDSA、Ed25519、ECDH、X25519、ElGamal 和密钥编码 |
| [SM2](sm2.md) | 签名、加解密、身份标识和带确认的密钥交换 |
| [SM9](sm9.md) | 基于身份的签名、加解密和密钥封装 |
| [后量子算法](pqc.md) | ML-KEM、ML-DSA、SLH-DSA 的参数集、编码和接口 |
| [第三方源码与许可证](../THIRD_PARTY.md) | 本地适配源码的来源、许可证和边界 |
| [NIST ACVP 测试样本](../pqc/testdata/README.md) | 固定向量来源、覆盖范围和重建方法 |

## 目录约定

- 根目录提供 `cryptoutils` 包的公开函数、链式适配和通用工具；文件按功能命名。
- `sm2/`、`sm3/`、`sm4/`、`sm9/`、`zuc/`、`pqc/` 存放相应算法实现；`rc4/`、`utils/` 保留兼容接口。
- `internal/` 存放非公开实现；算法子包内的参考实现保留各自的来源记录和许可证。
- `*_test.go` 与被测代码放在同一目录；`testdata/` 保存可复现的公开测试向量和辅助脚本。
- `docs/` 按算法类别维护使用说明；根目录 README 保留快速入口与兼容性说明。

测试向量中的固定密钥仅用于验证实现。各文档中的编码、参数限制和使用条件也是 API 约定的一部分。
