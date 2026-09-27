# 对称加密、模式与 MAC

所有链式接口继续通过 `SetKey(key)` 设置二进制密钥，使用 `Result()` 返回结果与错误；密文是原始字节，按需追加 `Hex()` 或 `Base64Encode()`。首次错误停止后续操作，`Reset()` 恢复输入。

## 认证加密

```go
p := cryptoutils.Init("hello")
p.SetKey(key)
encoded, err := p.AEADEncrypt("xchacha20-poly1305", aad).Base64Encode().Result()

q := cryptoutils.Init(encoded).Base64Decode()
q.SetKey(key)
plain, err := q.AEADDecrypt("xchacha20-poly1305", aad).Result()
```

纯函数 `EncryptAEAD(name, data, key, aad)` / `DecryptAEAD(name, data, key, aad)` 返回 `([]byte, error)`。

| name | 密钥字节 | 自动随机 nonce 字节 | 便捷链式方法前缀 |
| --- | --- | --- | --- |
| `aes-gcm` | 16/24/32 | 12 | `AESGCM` |
| `sm4-gcm` | 16 | 12 | `SM4GCM` |
| `aes-ccm` | 16/24/32 | 12 | `AESCCM` |
| `sm4-ccm` | 16 | 12 | `SM4CCM` |
| `chacha20-poly1305` | 32 | 12 | `ChaCha20Poly1305` |
| `xchacha20-poly1305` | 32 | 24 | `XChaCha20Poly1305` |

便捷方法均以 `Encrypt(aad)` / `Decrypt(aad)` 结尾。所有自动封装格式均为 `nonce || ciphertext || tag`，tag 为 16 字节；算法名称和 AAD 不包含在封装中，调用方需保存或约定它们。错误的 AAD、密钥、被修改或截断的密文都返回错误，不返回未认证的明文。12 字节随机 nonce 的同一密钥至多加密 2^32 条消息。默认 CCM 限制每条消息小于 2^24 字节。

需要对接已有 CCM 协议时可用 `SealCCM(name, data, key, nonce, aad, tagSize)` / `OpenCCM(...)`，其中 name 是 `aes` 或 `sm4`，nonce 长度为 7..13，tagSize 为偶数 4..16。其输出只包含 `ciphertext || tag`，nonce 由调用方单独传递且同一密钥下必须唯一；最大明文长度为 `2^(8*(15-len(nonce)))-1`。

## 分组算法与模式

`NewBlockCipher(name, key)` 返回标准 `cipher.Block`。支持 AES、SM4、DES、3DES、Blowfish、Twofish、TEA、XTEA、CAST5、IDEA。名称不区分大小写，可包含连字符，`tripledes` 和 `cast128` 是别名。

| 算法 | 密钥字节 | 分组字节 |
| --- | --- | --- |
| AES | 16/24/32 | 16 |
| SM4 | 16 | 16 |
| DES / 3DES | 8 / 24 | 8 |
| Blowfish | 1..56 | 8 |
| Twofish | 16/24/32 | 16 |
| TEA / XTEA / CAST5 / IDEA | 16 | 8 |

纯函数 `EncryptBlock(algorithm, mode, data, key, iv)` / `DecryptBlock(...)`；链式 `BlockEncrypt(algorithm, mode, iv)` / `BlockDecrypt(...)`。

- `CBC`、`ECB`：自动 PKCS#7 填充/去填充；`EncryptBlockRaw` / `DecryptBlockRaw` 关闭填充，要求整分组。
- `CTR`、`CFB`、`OFB`：不填充，支持任意字节长度；CFB 使用完整分组反馈。
- ECB 的 iv 必须为空，其余模式的 iv 必须恰好一个分组。CBC/CFB 要求不可预测的新 IV，CTR/OFB 要求同一密钥下不重复的初始状态；CTR 不得跨消息重叠计数器区间。
- 输出只有密文，不包含 IV，没有认证能力。CBC 的填充检查不能代替认证。使用这些模式时必须由上层协议正确认证密文和相关元数据。

AES 和 SM4 另有 `AESCBCEncrypt(iv)`、`SM4CTREncrypt(iv)` 等便捷方法：前缀 `AES`/`SM4` + 模式 `CBC`/`CTR`/`CFB`/`OFB`/`ECB` + `Encrypt`/`Decrypt`；ECB 不接收 IV。

`EncryptXTS(algorithm, data, key, sector)` / `DecryptXTS(...)` 用于整分组扇区，algorithm 可用 `aes`、`sm4` 或 `twofish`。key 是两个长度相同、内容不同的分组密钥拼接。数据必须非空、16 字节对齐且小于 2^24 字节；sector 是 uint64 小端扇区编号。链式为 `XTSEncrypt(algorithm, sector)` / `XTSDecrypt(...)`，AES 另有 `AESXTSEncrypt(sector)` / `AESXTSDecrypt(sector)`。当前不实现 ciphertext stealing；XTS 不提供认证。

DES、3DES、Blowfish、TEA、XTEA、CAST5、IDEA 主要用于历史协议兼容和研究；IDEA 为本地可移植实现，未实现恒定时间运算。原有 `DesCBCEncrypt()` 是带随机 IV 和 HMAC 的本库封装，和这里的裸 `BlockEncrypt("des", "cbc", iv)` 格式不同，见主 README 的迁移说明。

## CMAC、Poly1305

- `CMAC(algorithm, data, key)` 返回完整分组长度的原始标签；`VerifyCMAC(algorithm, data, key, tag)` 返回 `(bool, error)`。支持上面的 8/16 字节分组算法，通常选择 AES/SM4。
- `Poly1305(data, key)` / `VerifyPoly1305(data, key, tag)`：key 必须 32 字节，且必须是**每条消息独立的一次性密钥**。需要自动管理认证加密时使用 ChaCha20-Poly1305 AEAD。
- 链式 `CMAC(algorithm)` 使用 SetKey，`Poly1305(key)` 显式接收一次性密钥；两者输出十六进制文本，和 HMAC 一致。

## ZUC

`CryptZUC(data, key, iv)` 返回原始加/解密结果，链式为 `ZUCEncrypt(iv)` / `ZUCDecrypt(iv)`。支持 ZUC-128（key=16、iv=16 字节）与 ZUC-256（key=32、iv=23 字节，184 位紧凑 IV）。子包 `zuc.NewCipher(key, iv)` 提供标准 `cipher.Stream`，支持分片及同一缓冲区原地处理。

`ZUCMAC(data, key, iv, tagSize)` 返回原始标签；`VerifyZUCMAC(data, key, iv, tag)` 恒定时间比较。ZUC-128 的 tagSize=4；ZUC-256 为 4/8/16，单位字节。链式 `ZUCMAC(iv, tagSize)` 使用 SetKey，输出十六进制。非整字节协议可使用 `zuc.MACBits(data, bitLen, key, iv, tagSize)`，从高位开始处理指定比特数。

每条消息的 key/IV 对必须唯一，也不能跨加密与 MAC 复用。ZUC 加密本身没有认证，当前表查找实现不保证恒定时间。这里暴露的是原始 IV 接口；移动通信协议中的 COUNT/BEARER/DIRECTION 到 IV 的映射由上层负责。

实现与测试参考：[RFC 3610 CCM](https://www.rfc-editor.org/rfc/rfc3610)、[RFC 4493 CMAC](https://www.rfc-editor.org/rfc/rfc4493)、[RFC 8439 Poly1305](https://www.rfc-editor.org/rfc/rfc8439)、[GmSSL 复现的 ZUC 官方测试向量](https://github.com/guanzhi/GmSSL/blob/master/tests/zuctest.c)。这些项目没有新增到模块依赖。
