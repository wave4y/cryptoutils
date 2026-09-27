# RSA 数学与 CTF 接口

根包 `github.com/wave4y/cryptoutils` 提供统一公开接口，`rsactf` 子包承载基于
Go 标准库 `math/big` 的数学实现，也可直接导入使用。
它接受小模数和任意长度的整数指数，也支持仅有 n/d/c、p/q/dp/dq 等题目参数。
这些是可变时间、无填充的研究接口；应用中的加密和签名继续使用根包的 OAEP/PSS。
现有标准 RSA 公私钥检查与密文格式保持原有约定。

## 裸模幂与字节编码

```go
package main

import (
    "fmt"
    "log"
    "math/big"

    "github.com/wave4y/cryptoutils"
)

func main() {
    m, err := cryptoutils.DecryptRSARaw(big.NewInt(3233), big.NewInt(2753), big.NewInt(2790))
    if err != nil {
        log.Fatal(err)
    }
    plaintext, err := cryptoutils.RSAIntegerToBytes(m, 0)
    if err != nil {
        log.Fatal(err)
    }
    fmt.Println(string(plaintext)) // A
}
```

| 函数 | 作用与输入要求 |
| --- | --- |
| `EncryptRSARaw(n,e,m)` | 返回 m^e mod n；n>1、e>0、0≤m<n。 |
| `DecryptRSARaw(n,d,c)` | 返回 c^d mod n；仅需要这三个参数，不需要构造标准私钥。 |
| `DecryptRSACRT(p,q,dp,dq,c)` | 对两个不同的奇素数（通过概率素性检查） 分别模幂并合并；需要 0<dp<p−1、0<dq<q−1。 |
| `RSAIntegerToBytes(x,width)` | 非负整数编码；width=0 为最短编码，0 编码为一个零字节；正 width 指定长度并左补零。 |

裸模幂不校验私钥数学关系，也不会解码 OAEP。`DecryptRSACRT` 没有 e，无法验证输入
CRT 指数是否对应题目的公钥。对于 p=q，使用正确私钥指数和 `DecryptRSARaw`；
φ(p²)=p(p−1)，但非单位明文可能有多个原像。字节宽度不能从整数恢复，按题目另行指定。


链式调用使用同一套根包实现：

```go
result, err := cryptoutils.Init("A").
    RSARawEncrypt(big.NewInt(3233), big.NewInt(17)).
    RSARawDecrypt(big.NewInt(3233), big.NewInt(2753), 0).
    Result() // result 为 []byte("A")
```

加密输出固定为模数字节宽度；解密宽度由第三个参数控制。空字节输入视为整数 0。
沿用链的首个错误保留约定：失败清空当前输出，后续操作停止，`Reset()` 恢复原输入。
因子、根和多组密文等数学结果使用纯函数，不隐式覆盖 `CryptoData` 字节状态。
子包使用同义短名称（如 `DecryptRaw`、`IntegerRoot`）；错误分别为 `ErrInvalidInput`、
`ErrNoResult`，与根包错误是同一实例。

## 数学原语和攻击

| 函数 | 条件与边界 |
| --- | --- |
| `RSAIntegerRoot(x,degree)` | 非负 x 的整数根，返回根、是否精确、错误；degree≥1。 |
| `RSACRT(moduli,residues)` | 至少两个模数，要求两两互素且每个余数在 [0,n) 内。 |
| `RSALowExponent(n,e,c,maxK)` | 对 k=0..maxK 尝试 c+k*n 的精确 e 次根；2≤e≤64。 |
| `RSABroadcast(moduli,ciphertexts,e)` | 同明文、同 e、互素模数；CRT 结果精确开根并验证所有观测，2≤e≤64。 |
| `RSACommonModulus(n,e1,c1,e2,c2)` | 同模同明文、互素正指数；负指数需要可逆密文。 |
| `RSASharedFactor(n1,n2)` | 返回两个模数共有且对二者均非平凡的因子。 |
| `RSAFermat(n,maxSteps)` | 搜索近因子，最多检查 maxSteps 个 a²−n；偶数直接返回 2。 |
| `RSAFactorFromPhi(n,phi)` | 根据两素数模数的 n 与 φ 恢复因子，检查判别式与输入关系。 |
| `RSAFactorFromCRTExponent(n,e,dp,attempts)` | 从底数 2 起有限次尝试 gcd(a^(e*dp−1)−1,n)；dp 可替换为 dq。 |

搜索预算是迭代次数，不是墙钟超时；一次大整数运算也可能耗时。方法未找到结果不证明
数学上无解。`RSACommonModulus` 不处理一般非互素指数；CRT 泄露仅提供 GCD 方法，
没有枚举 k 的回退。广播接口要求所有观测对应同一明文。

所有函数不修改传入的 `big.Int`。输入不符合条件时返回 `ErrInvalidRSACTFInput`，
攻击条件不成立或在预算内未找到结果时返回 `ErrRSACTFNoResult`，可用 `errors.Is` 判断。
`RSAIntegerRoot` 的非精确结果通过 bool 表达，不作为错误。

## 与标准 RSA 接口对接

恢复出合法的 n/e/d/p/q 后，可以构造 `crypto/rsa.PrivateKey`，再交给根包的
`DecryptRSAOAEP`、`SignRSAPSS` 或 PEM/DER 函数。只有原密文使用对应 OAEP 格式时
才能这样解密；裸 RSA 密文应使用 `DecryptRSARaw`。

标准接口仍要求 2048..8192 位模数、3..2³¹−1 的奇数 e，以及两个不同素因子的完整私钥。
攻击层的 e 是 `*big.Int`，在确认大小合规前不要强制转为 `int`。小模数题、大 e 题、
平方模数题的运算和字节输出可直接留在 rsactf 子包，不必经过标准 RSA 密钥类型。

## 范围与测试

本包当前提供以上数学原语，没有自动攻击调度或网络请求，也未集成 Wiener、Pollard、
Franklin–Reiter、格约简、FactorDB。可以在这些原语上扩展；本次接口不表示完整覆盖
所有 RSA 攻击。

```sh
go test ./rsactf
go test ./...
go vet ./...
```

测试包含普通和边界整数、精确根与失败预算、输入不被修改，以及从泄露 φ 恢复
2048 位密钥后对接 OAEP 和 PEM 的端到端样例。该样例主动提供 φ，不能视为破解
无泄露的正常 RSA。
