# 本地算法源码与来源

本库沿用已有的 `golang.org/x/crypto` 及其原有间接依赖 `golang.org/x/sys`，没有把下面的参考项目加入 Go 模块依赖。对于大型算法，本地适配必要的开放源码原语并保留来源和许可证；这不表示这些算法全部从零原创。

| 本地路径 | 来源版本 | 范围与许可证 |
| --- | --- | --- |
| `pqc/internal/reference` | [Cloudflare CIRCL v1.6.3](https://github.com/cloudflare/circl/tree/v1.6.3) | FIPS 203/204/205 所需算法与内部工具，BSD-3-Clause；见 [LICENSE](pqc/internal/reference/LICENSE) 和 [修改说明](pqc/internal/reference/README.md) |
| `sm9/internal/bn256` | [emmansun/gmsm v0.29.8](https://github.com/emmansun/gmsm/tree/v0.29.8/sm9/bn256) | SM9 所需配对运算的可移植 Go 子集，保留 [MIT](sm9/internal/bn256/LICENSE.MIT) 和 [BSD](sm9/internal/bn256/LICENSE.BSD) 许可 |

SM2、IDEA、CCM、CMAC、ZUC 的本地实现按相应算法定义编写，标准常量与公开测试向量用于校验。SM3/SM4 和已有模块实现保留原有来源说明。SM9 协议层及本库接口在这些原语上实现。

测试向量来自相应 RFC、国密标准示例、OpenSSL、GmSSL/gmsm 和 NIST ACVP。固定测试私钥仅为公开向量，不用于生成业务密钥。出处记录在对应测试或 testdata 文件中。

本地源码应随本库一起维护。通过标准向量和互操作测试不等同于获得 FIPS 模块验证，也不等同于独立密码学审计。SM2 通用大整数运算、SM9 协议层标量运算及部分传统原语仍有时序方面的限制，见相应算法文档。
