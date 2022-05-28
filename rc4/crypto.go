package utils

import (
	"crypto/md5"
	"crypto/rc4"
	"encoding/base64"
	"encoding/hex"
	"math/rand"
	"net/url"
	"time"
)

func Md5Encode(plain string) string {
	h := md5.New()
	h.Write([]byte(plain))
	cipherStr := h.Sum(nil)
	return hex.EncodeToString(cipherStr)
}

func Base64Encode(plain string) string {
	cipher := base64.StdEncoding.EncodeToString([]byte(plain))
	return string(cipher)
}

func Base64Decode(cipher string) (string, error) {
	plain, err := base64.StdEncoding.DecodeString(cipher)
	if err != nil {
		return "", err
	}
	return string(plain), nil
}

func HexEncode(plain string) string {
	return hex.EncodeToString([]byte(plain))
}

func HexDecode(cipher string) string {
	plain, err := hex.DecodeString(cipher)
	if err != nil {
		return ""
	}
	return string(plain)
}

func UrlDncode(plain string) string {
	return url.QueryEscape(plain)
}

func UrlDecode(cipher string) (string, error) {
	plain, err := url.QueryUnescape(cipher)
	if err != nil {
		return "", err
	}
	return plain, nil
}

func RandomString(l int) string {
	rand.Seed(time.Now().UnixNano() / 5)
	str := []byte("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")
	b := make([]byte, l)
	for i := range b {
		b[i] = str[rand.Intn(len(str))]
	}
	return string(b)
}

func Rc4Encrypt(plain string, key []byte) string {
	src := []byte(plain)
	cipher, err := rc4.NewCipher(key)
	if err != nil {
		return ""
	}
	dst := make([]byte, len(src))
	cipher.XORKeyStream(dst, src)
	return HexEncode(string(dst))
}

func Rc4Decrypt(plain string, key []byte) string {
	src := []byte(HexDecode(plain))
	cipher, err := rc4.NewCipher(key)
	if err != nil {
		return ""
	}
	dst := make([]byte, len(src))
	cipher.XORKeyStream(dst, src)
	return string(dst)
}

func main() {
	// cipher := md5encode("1")
	// fmt.Print(cipher)
	// plain := "YQ=="
	// plain2, err := base64decode(plain)
	// if err != nil {
	// 	return
	// }
	// fmt.Println(plain2)
	// b := "61616#```  }++   1"
	// // a, _ := hexdecode(b)
	// a := Urlencode(b)
	// fmt.Println(a)
	// fmt.Println(RandomString(5))

	// var key []byte = []byte("fd6cde7c2faaaaaaaaaaaaa4913f22297c948dd530c84")
	// cipher := Rc4Encrypt("helloworld", key)
	// plain := Rc4Decrypt("bc304151292024a78919", key)
	// // fmt.Println(HexDecode(string(plain)))
	// fmt.Println(cipher)
	// fmt.Println(plain)
	// a, _ := HexDecode("7789a81f0c8308713ab0")
	// rc4obj1, _ := rc4.NewCipher(key)
	// rc4str1 := []byte(a)
	// plaintext := make([]byte, len(rc4str1))
	// rc4obj1.XORKeyStream(plaintext, rc4str1)
	// // stringf1 := fmt.Sprintf("%x", plaintext)
	// stringf1 := HexEncode(string(plaintext))
	// fmt.Println(stringf1)
	// fmt.Println(HexDecode(stringf1))
}
