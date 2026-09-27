# 架构与测试组织

本库按公开入口、算法实现和测试用途分层。对外继续使用 `github.com/wave4y/cryptoutils` 及已有算法子包，内部目录的调整不改变公开函数、链式调用或密文格式。

## 职责

| 层级 | 位置 | 职责 |
| --- | --- | --- |
| 统一入口 | 根包 | `CryptoData` 链状态、编码、公开函数与算法链式适配。保持首个错误、输出编码和验证成功后的状态约定。 |
| 对称实现 | `internal/symmetric` | AEAD、分组模式、XTS、CCM、CMAC/Poly1305、填充、DES 兼容封装及参数检查。 |
| 传统公钥实现 | `internal/asymmetric` | RSA、ECDSA、Ed25519、ECDH、ElGamal 和 PEM/DER 密钥格式与校验。 |
| 摘要实现 | `internal/digest` | 固定摘要、HMAC 和 SHAKE 的计算、算法名称与输出长度检查。 |
| 派生与密码存储 | `internal/derivation` | PBKDF2、HKDF、scrypt、Argon2id、bcrypt、密码哈希格式与资源参数检查。 |
| 独立算法 | `sm2`、`sm3`、`sm4`、`sm9`、`zuc`、`pqc`、`rsactf` | 提供可直接导入的算法 API，不依赖根包的可变链。 |
| 内部原语 | `internal/idea`、算法包内的 `internal/` | 为上层算法服务，不向外部使用者开放；本地适配源码在这里保留来源和许可证。 |
| 兼容入口 | `utils`、`rc4` | 保留历史导入路径、类型别名和旧方法；迁移约定见 [兼容性说明](compatibility.md)。 |

根包 `symmetric.go`、`asymmetric.go`、`hash.go`、`kdf.go`、`password.go` 保留公开委托函数与链式方法；`*_api.go` 连接独立算法包。链式方法把结果或错误写回 `CryptoData`，`rsa_ctf_api.go` 同样委托 `rsactf` 并适配裸 RSA 链式操作，`rsa_ctf_parameters_api.go` 暴露 CTF 参数解析与补全，`rsa_ctf_context_api.go` 暴露原有搜索的 Context 入口，`rsa_factorization_api.go` 暴露 Wiener/Pollard 及其 Context 版本。算法计算和相应参数检查位于内部实现或独立算法子包，内部包不持有 `CryptoData`，也不反向导入根包。

```text
使用者
  ├── cryptoutils 根包：公开函数 / CryptoData
  │     ├── internal/symmetric ──→ sm4、internal/idea、标准库与原有依赖
  │     ├── internal/asymmetric ─→ 标准库与原有依赖
  │     ├── internal/digest ─────→ sm3、标准库与原有依赖
  │     ├── internal/derivation ─→ internal/digest、标准库与原有依赖
  │     └── sm2 / sm9 / zuc / pqc / rsactf
  └── 独立算法子包：直接使用类型化接口

utils 兼容入口 ──→ cryptoutils 根包
```

Go 的 `internal` 规则限制外部项目直接导入内部实现。公开错误、参数类型和函数仍从根包或原有算法包获取，调用方无需跟随内部文件迁移。

## 测试组织

| 位置 | 测试目的 | 典型内容 |
| --- | --- | --- |
| `tests/api/` | 从使用者视角验证根包公开 API | 链状态和错误传播、输入/输出副本、公开纯函数、兼容入口、加解密与签名互操作。 |
| 算法和内部实现包内的 `*_test.go` | 验证算法与实现边界 | SM3/SM4 等标准向量、分片与原地处理、规范编码、参数边界、内部计算与低层接口合约。 |
| 根目录 `example_test.go` | 提供可执行的 Go 文档示例 | `go test` 检查示例输出，Go 文档工具展示公开 API 的用法。 |
| 对应包的 `testdata/` | 保存可复现的输入和预期输出 | 公开固定向量、出处说明和必要重建脚本。 |

根包公开接口的回归测试按功能文件搬入 `tests/api`，继续导入公开包验证实际使用方式，保留原有测试覆盖。算法单元测试留在实现附近，便于验证局部边界。根目录只保留 `example_test.go` 这一份测试文件，用于公开文档示例。

`*_test.go` **不会编译进使用者程序**，只有运行 `go test` 时参与测试构建。`testdata/` 也不是常规 Go 包；其中向量由测试读取，不因使用本库而成为运行时数据。

```sh
# 所有包的测试，包括示例、公开 API 和算法单元测试
go test ./...

# 只运行公开 API 回归；将其调用的本模块实现计入覆盖率
go test -coverpkg=./... ./tests/api

# 汇总所有测试对本模块各包的覆盖率
go test -coverpkg=./... -coverprofile=coverage.out ./...
go tool cover -func=coverage.out

# 静态检查
go vet ./...
```

公开接口测试集中到 `tests/api` 后，只运行 `go test ./... -cover` 会按被测包分别统计覆盖，不能完整呈现跨包调用的覆盖率；需要整体统计时使用上面的 `-coverpkg=./...`。`coverage.out` 是命令生成的本地报告文件。

向量和互操作测试用于验证已知行为，不能替代独立密码学审计，也不构成 FIPS 模块验证。固定测试私钥只用于测试。后量子样本的具体范围见 [NIST ACVP 样本说明](../pqc/testdata/README.md)。

## 依赖与来源

模块需要 Go 1.22 或更高版本，继续使用原有 `golang.org/x/crypto` 及它原本依赖的 `golang.org/x/sys`，没有为本地适配算法新增 Go 模块依赖。

SM9 配对与后量子原语采用必要参考源码的本地适配，因此源码、补丁和许可证需要随本库维护；具体版本、改动范围与限制见 [第三方说明](../THIRD_PARTY.md)。运行时条件和算法限制见 [使用指南](usage.md#使用条件与实现边界) 以及各功能文档。

功能比较与实现研究的参考包括 [Go 标准库 crypto](https://pkg.go.dev/crypto)、[golang.org/x/crypto](https://pkg.go.dev/golang.org/x/crypto)、[Tink Go](https://github.com/tink-crypto/tink-go)、[emmansun/gmsm](https://github.com/emmansun/gmsm) 和 [deatil/go-cryptobin](https://github.com/deatil/go-cryptobin)。这些链接不表示新增模块依赖；实际采用其他项目时，应核对其版本要求、算法模式与密文格式。
