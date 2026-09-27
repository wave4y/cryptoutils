package cryptoutils_test

import (
	"crypto/rand"
	"fmt"
	c "github.com/wave4y/cryptoutils"
)

func ExampleCryptoData_Reset() {
	p := c.Init("abc")
	fmt.Println(p.Hex().String())
	fmt.Println(p.Reset().Base64Encode().String())
	// Output:
	// 616263
	// YWJj
}

func ExampleEncryptAESGCM() {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		panic(err)
	}
	aad := []byte("example:v1")
	encrypted, err := c.EncryptAESGCM([]byte("hello"), key, aad)
	if err != nil {
		panic(err)
	}
	plaintext, err := c.DecryptAESGCM(encrypted, key, aad)
	if err != nil {
		panic(err)
	}
	fmt.Println(string(plaintext))
	// Output: hello
}
