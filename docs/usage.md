# 使用指南

安装与最小示例见 [项目说明](../README.md)。本页介绍所有链式 API 共享的状态、输出和错误约定，以及 AES-GCM 的完整用法。算法参数与接口列表见 [文档导航](README.md)。

## 链式调用与错误处理

`Init → SetKey/变换 → Result` 是基本调用流程。`SetKey` 设置二进制对称密钥；公钥算法的公私钥通过显式类型参数传入。密钥生成和需要多个返回值的操作使用独立函数。

```go
p := cryptoutils.Init("abc").Hash("SHA-256")
result, err := p.Result()
if err != nil {
    return err
}
fmt.Println(string(result))
```

上面的片段放在返回 `error` 的函数内，并导入 `fmt` 和 `github.com/wave4y/cryptoutils`。实际调用应检查 `Result()` 返回的错误。

| 操作 | 行为 |
| --- | --- |
| `Init(src)` | 接收 `string`、`[]byte` 或 `nil`，复制输入；`nil` 表示空数据，其他类型产生初始化错误。 |
| `SetKey(key)` | 复制密钥，不清除已有错误；此方法没有返回值，应单独调用。 |
| 变换方法 | 修改当前数据并返回链对象；首个错误发生后，后续变换停止。 |
| `Result()` | 返回当前数据的副本与错误；失败时数据为 nil。 |
| `String()` / `Bytes()` | 读取当前数据，不改变状态；`Bytes()` 返回副本。失败时分别返回空字符串或 nil，需同时检查 `Err()`。 |
| `Err()` | 返回首个错误；用它区分失败与合法空数据。 |
| `Reset()` | 恢复最初输入、清除处理错误并保留密钥；非法输入类型造成的初始化错误不能清除。 |

同一个链对象可变，不支持多个 goroutine 同时操作。需要并发处理时，为每次处理分别调用 `Init`。

重复处理最初输入时显式重置：

```go
p := cryptoutils.Init("abc")
fmt.Println(p.Hex().String())                  // 616263
fmt.Println(p.Reset().Base64Encode().String()) // YWJj
```

签名验证、密码哈希校验等链式方法在成功后保留当前输入，失败时记录错误；生成签名则把当前数据替换为签名。具体接口见对应算法文档。

## 文本与原始字节

固定摘要方法（如 `Md5()`、`Sha256()`、`Sm3()`、`Hash(name)`）以及 HMAC、CMAC、Poly1305 等 MAC 链式方法默认输出小写十六进制文本。`Hash("SHA-256")` 支持大小写和连字符写法，完整算法别名见 [摘要文档](hash-kdf.md)。

`HashBytes(name)`、`HMACBytes(...)` 和 `Shake128Bytes/Shake256Bytes` 输出原始字节。加密、签名、密钥派生也输出原始字节，需要文本传输时再调用 `Base64Encode()` 或 `Hex()`。

下面两个链处理的字节不同：

```go
// 对 32 字节 SHA-256 摘要做 Base64。
rawDigest, err := cryptoutils.Init("abc").HashBytes("sha256").Base64Encode().Result()

// 对 64 字节十六进制摘要文本做 Base64。
hexDigest, err := cryptoutils.Init("abc").Sha256().Base64Encode().Result()
```

这是两种独立写法的对照，实际代码应分别检查每个 `err`。`HexDecode()` 和 `Base64Decode()` 在解码失败时记录错误，不返回部分结果。

## AES-GCM

`EncryptAESGCM(data, key, aad)` / `DecryptAESGCM(data, key, aad)` 支持 16、24、32 字节 AES 密钥。加密自动生成 12 字节随机 nonce，二进制格式为 `nonce || ciphertext || tag`，标签为 16 字节。解密验证标签后才返回明文；AAD 是附加认证数据，不保存在输出中，加解密时必须一致。

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
    aad := []byte("example:v1")
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

链式方法为 `AESGCMEncrypt(aad)` / `AESGCMDecrypt(aad)`。以下函数演示在传输前后加上 Base64 编解码；放在导入 `github.com/wave4y/cryptoutils` 的包内使用：

```go
func roundTrip(key, message, aad []byte) ([]byte, error) {
    p := cryptoutils.Init(message)
    p.SetKey(key)
    encoded, err := p.AESGCMEncrypt(aad).Base64Encode().Result()
    if err != nil {
        return nil, err
    }

    d := cryptoutils.Init(encoded).Base64Decode()
    d.SetKey(key)
    return d.AESGCMDecrypt(aad).Result()
}
```

同一密钥使用这种随机 nonce 格式时，最多加密 2^32 条消息。`key` 是二进制密钥，不是用户密码；密码存储使用 [bcrypt 或 Argon2id](hash-kdf.md)。其余 AEAD、外部 nonce 接口及分组模式见 [对称加密文档](symmetric.md)。

## HMAC 与填充

- `HMACSHA256(data, key)` 返回原始标签；`VerifyHMACSHA256(data, key, tag)` 使用恒定时间比较验证标签。链式 `Init(data).HMACSHA256(key)` 输出十六进制文本。
- 通用 `HMAC`、`VerifyHMAC` 与链式 `HMACBytes` 支持更多摘要，参数顺序和返回值见 [摘要文档](hash-kdf.md)。
- `PKCS7Padding(data, blockSize)` / `PKCS7UnPadding(data, blockSize)` 返回 `([]byte, error)`，检查块大小、数据长度和全部填充字节，并返回独立副本。AES 的块大小始终是 16 字节，与密钥长度无关。
- 填充检查不提供消息认证；使用裸 CBC 等模式时，上层协议必须认证密文和相关元数据。旧 PKCS#5 接口的行为变化见 [兼容性说明](compatibility.md#填充接口)。

## 使用条件与实现边界

新业务优先采用认证加密。DES、RC4、MD4/MD5 等传统算法以及无认证的分组模式主要用于历史协议、研究与 CTF，各算法的具体限制见功能文档。`sm4.NewCipher` 返回标准 `cipher.Block`，只处理一个分组；非法缓冲区遵循该底层接口的约定触发 panic，消息加解密可使用根包接口。

SM2 的通用大整数实现、SM9 协议层标量运算、IDEA 和 ZUC 表查找等实现尚不保证恒定时间。测试向量与互操作测试不等同于独立密码学审计，也不代表 FIPS 模块验证。第三方源码的本地适配、许可证与维护边界见 [来源说明](../THIRD_PARTY.md)。
