package cryptoutils

import "fmt"

func checkErr(err error, module string) {
	if err != nil {
		fmt.Println("module: ", module, " error: ", err)
	}
}
