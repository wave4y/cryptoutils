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

### 参数解析与补全

| 函数或类型 | 作用 |
| --- | --- |
| `ParseRSAPublicParametersDER(data)` | 读取 PKCS#1 或 PKIX 公钥，返回 `RSAPublicParameters`，n/e 均为 `*big.Int`。 |
| `ParseRSAPublicParametersPEM(data)` | 读取单个 `RSA PUBLIC KEY` 或 `PUBLIC KEY` 块。 |
| `RSACompletePrivateParameters(p,q,e)` | 校验两个不同奇素数及指数可逆性，返回 `RSAPrivateParameters`。 |
| `RSAPrivateExponent(e,totient)` | 返回 e 对给定 φ 或 λ 的最小正模逆；无法单独验证 totient 属于哪个 n。 |

CTF 公钥解析接受 n>1、e>0，支持小模数和任意长度指数；它只解析数学参数，不保证
这些参数满足标准 RSA 的安全策略。DER/PEM 分别最多 64/128 KiB，拒绝尾随数据、额外
字段、多 PEM 块、错误块类型与非 RSA 算法。PKIX 的 rsaEncryption 参数接受 NULL 或省略。
标准 `ParsePublicKeyDER/PEM` 继续使用应用级密钥校验。

私钥补全要求 e>1，并返回 N、E、P、Q、Phi、Lambda、D、DP、DQ。
其中 `D = e⁻¹ mod Lambda`，可能不同于对 Phi 求逆的值，两者均可用于对应的两素数 RSA。
输入不变，所有输出整数彼此独立；调用者修改这些可变字段后需自行保持参数关系。
不互素指数返回 `ErrRSACTFNoResult`，合数因子、相同因子及其他非法输入返回
`ErrInvalidRSACTFInput`；平方模数和多素数模数不使用这个补全函数。

```go
params, err := cryptoutils.RSACompletePrivateParameters(big.NewInt(61), big.NewInt(53), big.NewInt(17))
if err != nil {
    return err
}
message, err := cryptoutils.DecryptRSARaw(params.N, params.D, big.NewInt(2790))
// message == 65；params.D == 413，params.Lambda == 780。
```

子包对应 `ParsePublicKeyDER/PEM`、`CompletePrivateParameters`、`PrivateExponent` 和
`PublicParameters` / `PrivateParameters` 类型；根包类型是别名，不复制实现。

### 攻击接口

| 函数 | 条件与边界 |
| --- | --- |
| `RSAIntegerRoot(x,degree)` | 非负 x 的整数根，返回根、是否精确、错误；degree≥1。 |
| `RSACRT(moduli,residues)` | 至少两个模数，要求两两互素且每个余数在 [0,n) 内。 |
| `RSALowExponent(n,e,c,maxK)` | 对 k=0..maxK 尝试 c+k*n 的精确 e 次根；2≤e≤64。 |
| `RSABroadcast(moduli,ciphertexts,e)` | 同明文、同 e、互素模数；CRT 结果精确开根并验证所有观测，2≤e≤64。 |
| `RSACommonModulus(n,e1,c1,e2,c2)` | 同模同明文；支持互素指数及非互素指数的精确根分支，结果对两组观测验证。 |
| `RSASharedFactor(n1,n2)` | 返回两个模数共有且对二者均非平凡的因子。 |
| `RSAFermat(n,maxSteps)` | 搜索近因子，最多检查 maxSteps 个 a²−n；偶数直接返回 2。 |
| `RSAFactorFromPhi(n,phi)` | 根据两素数模数的 n 与 φ 恢复因子，检查判别式与输入关系。 |
| `RSAFactorFromCRTExponent(n,e,dp,attempts)` | 从底数 2 起有限次尝试 GCD，平凡结果增加重复平方回退；dp 可替换为 dq。 |
| `RSAWiener(n,e,maxConvergents)` | 枚举 e/n 的普通连分数收敛项，恢复小私钥指数对应的素因子；预算包含 e<n 时最初的 0/1 项。 |
| `RSAPollardPMinusOne(n,bound,attempts)` | Pollard p−1 第一阶段；bound≥2 为平滑界，attempts 为从 2 起尝试的底数数量。 |
| `RSAPollardRho(n,maxSteps,attempts)` | Brent 形式的 Pollard Rho；maxSteps 为全部重启和失败批次回放合计的多项式求值次数，attempts 限制重启次数。 |

搜索预算是迭代次数，不是墙钟超时；一次大整数运算也可能耗时。方法未找到结果不证明
数学上无解。共模非互素指数分支对 g=gcd(e1,e2) 尝试精确整数根，通常要求 m^g<n；
若密文不可逆而暴露了因子，则在 n 为两个不同素数之积且至少一个 e 对 λ(n) 可逆时
尝试解密，并对两组密文验证。它不是一般模方程求根器。
CRT 泄露的重复平方回退可处理直接 GCD 总得到 n 的部分情形，attempts 仍表示底数数量，
不引入无限搜索或枚举 k。广播接口要求所有观测对应同一明文。

所有函数不修改传入的 `big.Int`。输入不符合条件时返回 `ErrInvalidRSACTFInput`，
攻击条件不成立或在预算内未找到结果时返回 `ErrRSACTFNoResult`，可用 `errors.Is` 判断。
`RSAIntegerRoot` 的非精确结果通过 bool 表达，不作为错误。
平方根使用 `big.Int.Sqrt`，更高次数使用整数牛顿迭代，并以整数幂判断是否精确，
不依赖浮点精度。

Wiener 与两个 Pollard 接口统一返回一个非平凡因子，不返回 d。Wiener 会验证恢复的
两因子是不同的概率素数；Pollard 返回的因子可能仍是合数，调用方应继续分解或校验。
得到完整的双奇素数分解后，可直接调用 `RSACompletePrivateParameters(p,n/p,e)`。

```go
p, err := cryptoutils.RSAWiener(n, e, 10000)
if err != nil {
    return err
}
params, err := cryptoutils.RSACompletePrivateParameters(p, new(big.Int).Quo(n, p), e)
if err != nil {
    return err
}
plaintext, err := cryptoutils.DecryptRSARaw(n, params.D, ciphertext)
```

新算法的零预算不进行搜索：Wiener 的 maxConvergents=0、p−1 的 attempts=0，以及 Rho
任一预算为 0，均返回 `ErrRSACTFNoResult`。预算类型均为 uint64，支持取消且不修改输入。
p−1 使用固定大小分段筛，避免按 bound 分配巨型数组；这不限制运行时间，大 bound
仍可能耗时。p−1 在 GCD=n 时回放该素数幂，Rho 在失败 GCD 批次内逐步回放，减少错失
中间因子的情况；Rho 回放同样消耗总求值预算。

Wiener 仅搜索经典收敛项，没有半收敛项/Boneh–Durfee 扩展；p−1 尚无第二阶段。
这些有界算法失败不代表模数是素数或密钥安全。

### 搜索取消

`RSAIntegerRootContext`、`RSALowExponentContext`、`RSAFermatContext`、
`RSAFactorFromCRTExponentContext`、`RSAWienerContext`、`RSAPollardPMinusOneContext` 和
`RSAPollardRhoContext` 在原参数前增加 `context.Context`，支持取消和截止时间。
子包同样使用 `IntegerRootContext` 等名称；原接口调用后台 context，签名和预算语义不变。

```go
ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
defer cancel()
factor, err := cryptoutils.RSAFermatContext(ctx, n, 1_000_000)
```

取消返回 `context.Canceled` 或 `context.DeadlineExceeded`，不返回部分结果；nil context
返回 `ErrInvalidRSACTFInput`。检查点位于搜索循环、整数根迭代、dp 恢复的重复平方、
连分数枚举、p−1 素数生成及 Rho 多项式求值之间。Wiener 候选的双素数验证不能在内部
中断，验证返回后会再次检查取消。
这是协作式取消，不能中断单次 `math/big` 运算，也不会启动取消后仍在后台计算的 goroutine。
需要严格的进程级时间或内存上限时，调用方应使用独立进程。
`ErrRSACTFNoResult` 继续表示条件不满足或预算内未找到结果，与取消错误可以区分。

## 与标准 RSA 接口对接

恢复出合法的 n/e/d/p/q 后，可以构造 `crypto/rsa.PrivateKey`，再交给根包的
`DecryptRSAOAEP`、`SignRSAPSS` 或 PEM/DER 函数。只有原密文使用对应 OAEP 格式时
才能这样解密；裸 RSA 密文应使用 `DecryptRSARaw`。

标准接口仍要求 2048..8192 位模数、3..2³¹−1 的奇数 e，以及两个不同素因子的完整私钥。
攻击层的 e 是 `*big.Int`，在确认大小合规前不要强制转为 `int`。小模数题、大 e 题、
平方模数题的运算和字节输出可直接留在 rsactf 子包，不必经过标准 RSA 密钥类型。

## 范围与测试

本包当前提供以上数学原语和有界攻击，没有自动攻击调度或网络请求，也未集成
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

`rsactf/testdata/rsactftool.json` 固定了 RsaCtfTool 的四组真实参数及来源提交：
近素数 Fermat、Håstad 广播、非互素指数共模、cube_root 自测题。
回归测试同时核对期望明文和全部密文的重新加密结果。其中共模题的指数为 6/9，
现在直接由 `CommonModulus` 恢复整数明文 12。
Wiener 与 Pollard 测试另外固定了官方 wiener、boneh_durfee、small_q 参数，包含
真实密文的恢复与重新加密验证。样例文件名不限定算法：boneh_durfee 的这组弱参数
可以通过经典 Wiener 恢复，并不表示库已实现 Boneh–Durfee。
