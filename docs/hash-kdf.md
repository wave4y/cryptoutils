# 摘要、HMAC、密钥派生与密码哈希

这些接口沿用本库链式约定：第一次错误保存在 `Err()`，后续变换停止；使用 `Result()` 同时取得结果和错误，或用 `Reset()` 恢复原始输入。以下示例假定已经导入根包为 `cryptoutils`。

## 固定长度摘要

`Init(data).Hash(name)` 生成小写十六进制文本；`HashBytes(name)` 生成原始摘要字节。名称大小写不敏感，首尾空白以及名称中的 `-`、`_`、`/` 可省略。

| 名称 | 链式便捷方法 |
| --- | --- |
| `md4`、`md5`、`sha1` | `Md4()`、`Md5()`、`Sha1()` |
| `sha224`、`sha256`、`sha384`、`sha512` | `Sha224()`、`Sha256()`、`Sha384()`、`Sha512()` |
| `sha512/224`、`sha512/256` | `Sha512224()`、`Sha512256()` |
| `sha3-224`、`sha3-256`、`sha3-384`、`sha3-512` | `Sha3_224()`、`Sha3_256()`、`Sha3_384()`、`Sha3_512()` |
| `keccak256`、`keccak512` | `Keccak256()`、`Keccak512()` |
| `blake2b256`、`blake2b384`、`blake2b512` | `Blake2b256()`、`Blake2b384()`、`Blake2b512()` |
| `blake2s256` | `Blake2s256()` |
| `ripemd160`、`sm3` | `Ripemd160()`、`Sm3()` |

`blake2b` 是 `blake2b512` 的别名，`blake2s` 是 `blake2s256` 的别名；`legacykeccak256/512` 也可使用。Keccak 与 SHA-3 的域分离不同，结果不能互换。BLAKE2b 的不同长度使用对应的参数化算法，并非截取 BLAKE2b-512 的结果。这里的 BLAKE2 摘要接口不带密钥。

## SHAKE 可变长度输出

纯函数 `SHAKE128(data, length)`、`SHAKE256(data, length)` 返回 `([]byte, error)`。`length` 的单位是字节，允许 0 到 `MaxSHAKEOutput`（1 MiB）。

链式 `Shake128(length)`、`Shake256(length)` 返回十六进制文本；`Shake128Bytes(length)`、`Shake256Bytes(length)` 返回原始字节。`Hash("shake128")` 会报错，避免省略输出长度时产生歧义。

```go
digest, err := cryptoutils.Init("abc").HashBytes("SHA3-256").Base64Encode().Result()
xof, err := cryptoutils.Init("abc").Shake256Bytes(64).Result()
```

## 通用 HMAC

```go
tag, err := cryptoutils.HMAC(data, key, "sm3") // 原始完整标签
valid, err := cryptoutils.VerifyHMAC(data, key, tag, "sm3")
```

HMAC 接受上表所有固定长度摘要。`VerifyHMAC` 恒定时间比较完整标签，不接受截断标签；不匹配返回 `false, nil`，不支持的摘要返回错误。

`Init(data).HMAC(key, name)` 返回十六进制标签，`HMACBytes(key, name)` 返回原始标签。原来的 `HMACSHA256`、`VerifyHMACSHA256` 保留原签名和行为。MD4、MD5、SHA-1、RIPEMD-160 等旧摘要用于协议兼容时应由调用方明确选择。

## 密钥派生

纯函数统一返回原始 `([]byte, error)`；链式方法把当前输入作为 password/secret，输出原始密钥字节。它们不会自动写入 `SetKey`，也不会自动保存 salt。

| 纯函数 | 链式方法 | nil options 默认参数 |
| --- | --- | --- |
| `PBKDF2(password, salt, *PBKDF2Options)` | `PBKDF2(salt, options)` | SHA-256、600000 次、32 字节 |
| `HKDF(secret, salt, info, *HKDFOptions)` | `HKDF(salt, info, options)` | SHA-256、32 字节 |
| `Scrypt(password, salt, *ScryptOptions)` | `Scrypt(salt, options)` | N=32768、r=8、p=1、32 字节 |
| `Argon2id(password, salt, *Argon2idOptions)` | `Argon2id(salt, options)` | time=3、memory=65536 KiB、threads=4、32 字节 |

使用 `DefaultPBKDF2Options()`、`DefaultHKDFOptions()`、`DefaultScryptOptions()`、`DefaultArgon2idOptions()` 得到可修改的值。**只有 nil 指针采用默认值**；传入非 nil options 后，每个字段都按原值检查，缺失或无效值不会被静默替换。

```go
options := cryptoutils.DefaultArgon2idOptions()
options.Threads = 2
key, err := cryptoutils.Init(password).Argon2id(salt, &options).Result()
```

PBKDF2/HKDF 的 `Hash` 使用上面的统一名称。HKDF 用于已有密钥材料的派生，不用于提高密码猜测成本。使用 PBKDF2、scrypt、Argon2id 派生密码密钥时，调用方应生成随机 salt 并与参数一起保存；Argon2id 要求 salt 至少 8 字节。需要存储登录密码时，可以使用下一节的自含格式。

参数上限在调用算法和分配大块内存前检查，避免整数溢出和不受限分配：

- 每个 password/secret/salt/info 输入最多 1 MiB；通用 KDF 输出 1..65536 字节。
- PBKDF2：1..2000000 次，`ceil(output/hashSize) * iterations <= 4000000`。
- HKDF：另外要求输出不超过 `255 * hashSize`。
- scrypt：N 为 2..1048576 的二次幂，r 为 1..32，p 为 1..16；计算的工作缓冲区不超过 256 MiB，`N*r*p <= 16777216`。
- Argon2id：time 为 1..10，memory 为 8..262144 KiB，threads 为 1..16，输出为 4..1024 字节；`memory >= 8*threads` 且 `memory*time <= 524288`。

这些是单次调用的资源上限；服务器应自行控制并发验证数量。低成本参数支持协议兼容和测试，默认参数用于通常的起点，实际成本需按部署性能调整。

## 密码哈希与校验

```go
stored, err := cryptoutils.HashArgon2id(password, nil)
err = cryptoutils.VerifyArgon2id(password, stored)

bcryptHash, err := cryptoutils.HashBcrypt(password, 0)
err = cryptoutils.VerifyBcrypt(password, bcryptHash)
```

- `HashArgon2id(password, options)` 自动生成 16 字节随机 salt，返回 `$argon2id$v=19$m=...,t=...,p=...$salt$hash`，salt/hash 使用无填充标准 Base64。密码哈希长度限制为 16..64 字节。
- `VerifyArgon2id(password, stored)` 在计算前校验格式和全部参数，执行相同资源上限；接受 8..64 字节 salt，只接受 Argon2id v19、规范十进制参数和 `m,t,p` 参数顺序。
- `HashBcrypt(password, cost)` 自动生成 salt；cost=0 使用 12，显式允许 4..14。超过 72 **字节**的密码报错，不截断。
- `VerifyBcrypt(password, stored)` 支持 `$2a$`、`$2b$`、`$2y$`，先检查 60 字节格式与 cost 上限 14，再进行计算。高于上限的已有 hash 会报错，而不会触发昂贵计算。
- 密码不匹配返回 `ErrPasswordMismatch`；损坏、未知格式或超出验证预算的 hash 返回 `ErrInvalidPasswordHash`。可使用 `errors.Is` 区分。

链式 `HashArgon2id(options)`、`HashBcrypt(cost)` 生成同样的存储文本；`VerifyArgon2id(stored)`、`VerifyBcrypt(stored)` 把当前数据当作待验证密码，成功时保留当前输入，失败时设置首个错误并清空结果。

```go
encoded, err := cryptoutils.Init(password).HashArgon2id(nil).Result()
verified := cryptoutils.Init(password).VerifyArgon2id(string(encoded))
if err := verified.Err(); err != nil {
    // 处理密码不匹配或无效存储格式。
}
```
