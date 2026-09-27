# SM2

`sm2` 子包本地实现 GB/T 32918 的推荐 256 位曲线、SM3 身份绑定签名、C1C3C2 加密以及带身份与密钥确认的密钥交换。根包提供同样的链式使用方式。

**实现限制：**当前采用 Go 通用 `elliptic.CurveParams` 和 `math/big` 运算，私钥操作不保证恒定时间。这是可验证的互操作实现，尚未经过独立密码学审计，不应把标准向量通过等同于抗侧信道认证。

## 密钥

`GenerateSM2Key()` 返回 `(*SM2PrivateKey, error)`，公钥为 `&private.PublicKey`。

- `ParseSM2PrivateKey(raw)`：32 字节大端标量，范围 1..n-2；`private.Bytes()` 返回同样的格式。
- `ParseSM2PublicKey(raw)`：65 字节 SEC1 非压缩点 `04 || x || y`；`public.Bytes()` 返回同样的格式。
- 输入点必须在指定曲线上，坐标必须在域内；私钥与附带公钥的一致性也会检查。
- 导出的 key 对象包含 `big.Int` 指针，使用中不得同时修改。

## 签名与加密

```go
private, err := cryptoutils.GenerateSM2Key()
if err != nil { return err }
public := &private.PublicKey

signature, err := cryptoutils.Init("hello").SM2Sign(private, nil).Result()
if err != nil { return err }
err = cryptoutils.Init("hello").SM2Verify(public, nil, signature).Err()
if err != nil { return err }

ciphertext, err := cryptoutils.Init("hello").SM2Encrypt(public).Result()
if err != nil { return err }
plaintext, err := cryptoutils.Init(ciphertext).SM2Decrypt(private).Result()
```

纯函数分别为 `SignSM2(data, uid, private)`、`VerifySM2(data, uid, signature, public)`、`EncryptSM2(data, public)`、`DecryptSM2(data, private)`。签名函数返回 ASN.1 DER `(r,s)`；验签函数返回 error，链式验签成功保留消息，失败清空数据并设置错误。

uid=nil 使用默认身份 `1234567812345678`；显式空切片是空身份，二者不同。uid 最多 8191 字节。签名内部计算 `SM3(ZA || message)`，业务应传入原始消息；`sm2.VerifyDigest` 仅用于已正确计算摘要的协议互操作。

根包密文格式为 `04 || C1.x(32) || C1.y(32) || C3(32) || C2`，最小 98 字节，允许明文长度 1..16 MiB。需要 ASN.1 格式的协议可用 `sm2.EncryptASN1(nil, public, data)` / `sm2.DecryptASN1(private, ciphertext)`，格式为 DER `SEQUENCE(x, y, C3, C2)`。认证失败不返回明文。

## 密钥交换

双方分别持有自己的长期私钥和本次生成的一次性临时私钥，并已可信地取得对方的长期公钥；交换临时公钥后调用：

```go
a, err := cryptoutils.ExchangeSM2(aPrivate, aEphemeral, bPublic, bEphemeralPublic,
    []byte("Alice"), []byte("Bob"), true, 32)
b, err := cryptoutils.ExchangeSM2(bPrivate, bEphemeral, aPublic, aEphemeralPublic,
    []byte("Bob"), []byte("Alice"), false, 32)
// 实际协议中每一行只在对应一方执行，并分别检查 err。
// 通过协议交换 Confirmation()，只有确认成功才取得会话密钥。
aKey, err := a.Confirm(b.Confirmation())
bKey, err := b.Confirm(a.Confirmation())
```

`initiator` 指明是否为发起方 A，身份顺序始终为自己、对方。keyLen 为 1..65536 字节。临时私钥必须和长期私钥不同，每次会话重新生成；本库不能跨进程跟踪临时密钥是否复用。确认失败返回错误，结果对象不提前暴露会话密钥。

固定向量来源：[GB/T 32918.5/GM/T 0003.5 示例在 OpenSSL 的测试](https://github.com/openssl/openssl/blob/master/test/sm2_internal_test.c)、[OpenSSL EVP SM2 互操作测试](https://github.com/openssl/openssl/blob/master/test/recipes/30-test_evp_data/evppkey_sm2.txt)。测试覆盖确定性签名、确定性加密、解密、身份绑定、非法点、DER 尾随数据、篡改及双方密钥确认。
