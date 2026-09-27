# SM9：本地标识密码实现

实现 GB/T 38635.1-2020、GB/T 38635.2-2020 固定参数下的标识签名/验签、密钥封装/解封装和标识加解密。签名 HID 固定为 `0x01`，加密及 KEM HID 固定为 `0x03`。身份是原样处理的字节串；库不自动做 Unicode、大小写或账户名规范化。

SM9 所需的素域、扩域、G1/G2 群与 R-Ate 配对代码位于本仓 `sm9/internal/bn256`。协议层的 H1/H2、KDF 和身份私钥派生也在本仓执行；SM3、SM4 使用现有本地实现。没有引入 gmsm 或其他新模块依赖，没有运行时网络访问。

## 根包接口

| 用途 | API |
| --- | --- |
| 创建签名主密钥 | `GenerateSM9SignMasterKey()` |
| 创建加密主密钥 | `GenerateSM9EncryptMasterKey()` |
| 导出主公钥 | `master.Public()` |
| 按身份派生用户私钥 | `master.Extract(identity)` |
| 签名 / 验签 | `SignSM9(message, key)` / `VerifySM9(message, identity, signature, masterPublic)` |
| 默认 XOR 构造加解密 | `EncryptSM9(plaintext, identity, masterPublic)` / `DecryptSM9(ciphertext, identity, userPrivate)` |
| 选择加密构造 | `EncryptSM9WithMode(...)` / `DecryptSM9WithMode(...)`，最后参数是 `SM9XOR` 或 `SM9SM4ECB` |
| 密钥封装 | `EncapsulateSM9(identity, masterPublic, keySize)`，返回 `encapsulation, sharedSecret, error` |
| 密钥解封装 | `DecapsulateSM9(encapsulation, identity, userPrivate, keySize)` |
| 导出密钥 | 各类型的 `MarshalBinary()` |
| 导入主密钥/主公钥 | `ParseSM9SignMasterPrivateKey`、`ParseSM9SignMasterPublicKey`、`ParseSM9EncryptMasterPrivateKey`、`ParseSM9EncryptMasterPublicKey` |
| 导入用户私钥 | `ParseSM9SignPrivateKey(raw, identity, masterPublic)` / `ParseSM9EncryptPrivateKey(raw, identity, masterPublic)` |

主密钥类型分别为 `SM9SignMasterPrivateKey`、`SM9EncryptMasterPrivateKey`，用户私钥分别为 `SM9SignPrivateKey`、`SM9EncryptPrivateKey`。用户私钥导入时会验证与身份和主公钥的配对关系。

链式接口的密钥放第一个参数：`SM9Sign(key)`、`SM9Verify(masterPublic, identity, signature)`、`SM9Encrypt(masterPublic, identity)`、`SM9Decrypt(userPrivate, identity)`；两个 `WithMode` 变体最后追加模式参数。签名直接处理当前消息字节，不隐式预哈希。输出是二进制；需要文本时显式接 `.Hex()` 或 `.Base64Encode()`。验签成功保留原消息，失败记录 sticky error 并清空当前结果，后续变换停止。

```go
// 放在返回 error 的函数中。生产 KGC 应独立、安全地保存主私钥。
master, err := cryptoutils.GenerateSM9SignMasterKey()
if err != nil { return err }
identity := []byte("alice@example.com")
userKey, err := master.Extract(identity)
if err != nil { return err }
message := []byte("message")
signature, err := cryptoutils.Init(message).SM9Sign(userKey).Result()
if err != nil { return err }
_, err = cryptoutils.Init(message).
    SM9Verify(master.Public(), identity, signature).Result()
return err
```

底层 `sm9` 包提供对应函数，并允许向生成/签名/封装/加密传入 `io.Reader`。注意底层 `sm9.Encapsulate` 返回 `(key, encapsulation, error)`，根包 `EncapsulateSM9` 为了与其他 KEM 接口统一，返回 `(encapsulation, sharedSecret, error)`。`nil` 选择 `crypto/rand.Reader`；指定确定性 Reader 仅适合已知答案测试，不应在实际业务中固定随机标量。根包始终使用 `crypto/rand.Reader`。

## 编码

本实现使用固定长度的原始编码，不使用 ASN.1，也不附加 `0x04` 非压缩点前缀。与其他实现交换数据时需要显式对齐格式。

| 对象 | 字节布局 |
| --- | --- |
| 主私钥标量 | 32 字节大端，值在 `[1,N-1]` |
| G1（加密主公钥、签名用户私钥） | `x || y`，各 32 字节，共 64 字节 |
| G2（签名主公钥、加密用户私钥） | 标准 Fp² 分量顺序 `x_im || x_re || y_im || y_re`，共 128 字节 |
| 签名 | `h(32) || S_G1(64)`，共 96 字节 |
| KEM 封装 | `C1_G1(64)` |
| 加密密文 | `C1_G1(64) || C3_SM3(32) || C2` |

加密的 XOR 与 SM4-ECB 构造采用标准 `C3 = SM3(C2 || K2)`，其中 K2 为 32 字节派生密钥。SM4-ECB 使用 16 字节 K1 和 PKCS#7 填充。解密先验证 C3，再释放明文或检查填充。模式不写入原始密文：双方必须约定相同模式。默认 XOR 构造不需要块填充。

密钥导出不包含身份，导入用户私钥必须同时提供身份和主公钥。导入时严格拒绝长度不符、额外尾字节、坐标大于或等于域素数、非规范编码、无穷远点、曲线外点和非正确子群点。用户私钥还会绑定提供的身份。所有导出字节均为副本。

## 边界与安全属性

- 身份长度为 1–65,535 字节；签名消息最大 16 MiB，允许空消息；加密明文长度为 1 字节至 16 MiB。
- KEM 输出长度以**字节**计，范围 1 字节至 1 MiB。超出范围在分配结果前返回错误。随机标量拒绝采样有重试上限，错误随机源不会造成无限循环。
- SM9 的 KGC 持有主私钥，可推导任何身份私钥，这是身份密码体系的固有密钥托管性质。身份有效期、撤销和用途应由上层身份命名与密钥管理协议定义。
- KEM 本身不认证封装者或业务消息。有效曲线点的替换可能导出不同的 key，必须配合上层认证协议。加密的 C3 检测密文破坏，但不证明发送者身份。
- SM4-ECB 是标准示例中的块加密构造，仍会泄露同一消息内相同分组的关系；默认使用标准 XOR 构造。
- 配对实现选择可移植纯 Go 路径。协议层标量派生和签名标量运算使用 `math/big`，**不承诺完整恒定时间或抵抗共享机器上的计时/缓存侧信道**。本地实现与通过标准向量不等于独立安全审计或密码产品认证。
- 密钥对象没有修改其内部标量/曲线点的公开方法；不要并发覆盖整个密钥对象。库不承诺 Go GC 管理的秘密内存可被可靠擦除。

## 测试与来源

```sh
go test ./sm9/... -count=1
go test . -run SM9 -count=1
go vet ./sm9/...
```

`sm9/sm9_test.go` 对以下公开 SM9 例子逐字节比较预先给定的期望值，并非只做内部往返：

1. Alice 的 H1，`Chinese IBS standard` 的签名 h 和 S（参考测试的 Appendix A）。
2. Bob 的加密主公钥、身份私钥、KEM C1 和 32 字节密钥（Appendix C）。
3. `Chinese IBE standard` 的 XOR 密文和 SM4-ECB 密文（Appendix D / block mode）。

向量见 [gmsm v0.29.8 的 SM9 测试](https://github.com/emmansun/gmsm/blob/v0.29.8/sm9/sm9_test.go)。另外保留了该版本的固定配对输出、最终幂运算和素域算术测试。额外测试覆盖篡改、身份错配、空/零值密钥、随机源失败、资源上限、字节所有权、非法点与根链式错误传播。

配对子集源自 [emmansun/gmsm v0.29.8](https://github.com/emmansun/gmsm/tree/v0.29.8/sm9/bn256)，包含其 MIT 许可与继承的 Go BSD-3-Clause 许可。完整原文、逐文件原始 SHA-256 和本地改动说明位于 `sm9/internal/bn256/LICENSE.MIT`、`LICENSE.BSD`、`UPSTREAM_SHA256.txt`、`README.md`。仅移植所需的 1-2-4-12 扩域纯 Go 子集；未复制完整外部库或增加 go.mod 依赖。

本地还修复了参考版本 G1 解码忽略坐标越界错误的问题：`(p,p)` 不能被约减并当作无穷远点接受。协议入口同时做解码后非零、规范序列化一致和子群校验，对每个 G1/G2 坐标的 p 边界有回归测试。
