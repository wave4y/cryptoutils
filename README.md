# CryptoUtils

用go实现的密码学套件

## 用法

```go
package main

import(

)

func main(){
	a := cryptoutils.Init("aaa")
	fmt.Println(a.Md5().String())
}
```

## todo
1. 添加国密算法 ` go get -u github.com/tjfoc/gmsm `