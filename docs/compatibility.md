# 兼容性与迁移

本页保留旧模块路径、链式行为和历史密文的迁移约定。当前用法见 [使用指南](usage.md)，算法格式与参数见 [文档导航](README.md)。

## 模块路径与目录调整

当前模块路径为 `github.com/wave4y/cryptoutils`，需要 Go 1.22 或更高版本。从旧模块路径迁移时，将根包和子包的 import 前缀统一替换，再运行 `go mod tidy`：

```go
import "github.com/wave4y/cryptoutils"
import "github.com/wave4y/cryptoutils/sm2"
```

实现分层后，根包仍提供原有公开函数与链式方法。`sm2`、`sm3`、`sm4`、`sm9`、`zuc`、`pqc`、`utils`、`rc4` 的公开导入路径保持不变；调用方不需要导入新的 `internal/symmetric` 或 `internal/asymmetric`。这些目录受 Go 的 `internal` 可见性约束，也不作为外部 API。

`utils.CryptoData` 是根包 `CryptoData` 的类型别名，`utils.Init` 委托给根包，沿用相同状态和错误处理约定。新代码可直接使用根包。

## 链式行为

`String()` 和 `Bytes()` 只读取当前结果，不再消耗或重置链；需要重新处理最初输入时显式调用 `Reset()`。`Bytes()`、`Result()` 返回副本，`Init` 和 `SetKey` 复制传入数据。

首个错误会停止后续变换，编码失败不返回部分结果，未知摘要名称通过错误报告。旧代码如果只读取 `String()`，应改为 `Result()`，或同时检查 `Err()`，否则空字符串可能掩盖失败。

`Reset()` 恢复最初输入、清除处理错误并保留密钥；非法输入类型造成的初始化错误不能清除。`SetKey` 不清除错误，也没有链式返回值。

## DES 密文格式

`DesCBCEncrypt()` / `DesDecrypt()` 保留方法名和 8 字节密钥要求，现在使用本库带认证的存储封装：

```text
"CU-DES\x01"（7 字节） || 随机 IV（8 字节） || CBC 密文 || HMAC-SHA256（32 字节）
```

认证覆盖版本前缀、IV 和密文；MAC 密钥用 HMAC-SHA256 从 DES key 和固定域 `cryptoutils/DES-CBC/HMAC-SHA256/v1` 派生。解密先验证认证标签。这是本库的存储格式，不是通用 DES 协议报文，也不同于 `EncryptBlock("des", "cbc", data, key, iv)` 返回的裸密文。

**新版密文不能被旧版库读取。** 旧版 `IV=key` 的裸密文必须显式调用 `DesDecryptLegacy()` 解密，新接口不自动降级。Legacy 不具备认证能力，只适合对来源可信的历史数据进行离线迁移；之后使用新密钥通过 AES-GCM 重新加密。

以下函数接收已经完成 Hex/Base64 解码的旧密文；放在导入 `github.com/wave4y/cryptoutils` 的包内使用：

```go
func migrateDES(oldCiphertext, oldKey, newAESKey []byte) ([]byte, error) {
    old := cryptoutils.Init(oldCiphertext)
    old.SetKey(oldKey)
    plaintext, err := old.DesDecryptLegacy().Result()
    if err != nil {
        return nil, err
    }
    return cryptoutils.EncryptAESGCM(plaintext, newAESKey, nil)
}
```

DES 的有效密钥长度不足以满足现代安全要求，加上认证也不能提高其抗穷举强度。兼容接口不等同于 AES-GCM 的安全级别。

## 填充接口

`PKCS5Padding` / `PKCS5UnPadding` 保留为弃用的 8 字节块兼容接口。`PKCS5Padding(data, blockSize)` 因旧签名不能返回 error，在 `blockSize != 8` 时返回 nil。

以前把 AES 的 16 字节块传给 `PKCS5Padding` 的代码，应改为 `PKCS7Padding(data, 16)` / `PKCS7UnPadding(data, 16)`，并处理返回的错误。PKCS#7 接口严格检查输入与全部填充字节，返回独立副本。

## RC4、编码与随机字符串

`rc4` 目录保留原来的包名 `utils`，导入时建议使用别名：

```go
import legacyrc4 "github.com/wave4y/cryptoutils/rc4"
```

RC4 密文继续使用十六进制编码，只适用于旧协议或 CTF。它不适合保护新业务数据。

| 旧接口 | 带错误返回的接口 |
| --- | --- |
| `Rc4Encrypt` | `RC4Encrypt` |
| `Rc4Decrypt` | `RC4Decrypt` |
| `HexDecode` | `HexDecodeE` |
| `RandomString` | `RandomStringE` |

新接口均返回 `(string, error)`；旧的单值包装保留并标为弃用，失败时返回空字符串。`UrlEncode` 修正 `UrlDncode` 的拼写，旧名仍为别名。

随机字符串使用 `crypto/rand` 和无偏采样，不再修改全局伪随机数状态。`utils` 中的 shell 转义辅助函数按 UTF-8 字节处理字符串，中文等非 ASCII 输入也能正确还原。
