# 文档导航

从 [项目说明](../README.md) 安装并运行最小示例，再按使用目的查阅：

| 文档 | 内容 |
| --- | --- |
| [使用指南](usage.md) | 链式状态、错误处理、文本与原始字节、AES-GCM 示例、HMAC 与填充 |
| [兼容性与迁移](compatibility.md) | 模块路径迁移、链式行为、DES 历史密文、PKCS#5、RC4 和旧方法 |
| [架构与测试组织](architecture.md) | 根包与内部实现职责、依赖方向、`tests/api`、算法单元测试和覆盖率命令 |
| [摘要、HMAC、密钥派生和密码哈希](hash-kdf.md) | 摘要算法、SHAKE、通用 HMAC、PBKDF2、HKDF、scrypt、Argon2id、bcrypt |
| [对称加密、模式与 MAC](symmetric.md) | AEAD、分组模式、CCM、XTS、CMAC、Poly1305、ZUC |
| [RSA 数学与 CTF](rsa-ctf.md) | 裸模幂、CRT、整数根及有限预算的 RSA 攻击 |
| [公钥、签名、密钥协商与 PEM/DER](public-key.md) | RSA、ECDSA、Ed25519、ECDH、X25519、ElGamal 和密钥编码 |
| [SM2](sm2.md) | 签名、加解密、身份标识和带确认的密钥交换 |
| [SM9](sm9.md) | 基于身份的签名、加解密和密钥封装 |
| [后量子算法](pqc.md) | ML-KEM、ML-DSA、SLH-DSA 的参数集、编码和接口 |
| [第三方源码与许可证](../THIRD_PARTY.md) | 本地适配源码的来源、许可证和维护边界 |
| [NIST ACVP 测试样本](../pqc/testdata/README.md) | 固定向量来源、覆盖范围和重建方法 |

根包公开 API 的回归测试集中在 `tests/api/`；算法单元测试留在对应包，根目录的 `example_test.go` 保留可执行文档示例。测试文件不编译进使用者程序，详细目录规则见 [架构说明](architecture.md)。

各文档中的编码、参数限制和使用条件属于 API 约定。测试向量中的固定密钥仅用于验证实现。
