package cryptoutils_test

import (
	"crypto/rand"
	"fmt"
	"math/big"

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

func ExampleDecryptRSARaw() {
	m, err := c.DecryptRSARaw(big.NewInt(3233), big.NewInt(2753), big.NewInt(2790))
	if err != nil {
		panic(err)
	}
	plaintext, err := c.RSAIntegerToBytes(m, 0)
	if err != nil {
		panic(err)
	}
	fmt.Println(string(plaintext))
	// Output: A
}

func ExampleCryptoData_RSARawEncrypt() {
	result, err := c.Init("A").
		RSARawEncrypt(big.NewInt(3233), big.NewInt(17)).
		RSARawDecrypt(big.NewInt(3233), big.NewInt(2753), 0).
		Result()
	if err != nil {
		panic(err)
	}
	fmt.Println(string(result))
	// Output: A
}
