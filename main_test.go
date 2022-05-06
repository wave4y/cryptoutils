package cryptoutils_test

import (
	"bytes"
	"cryproutils/utils"
	"crypto/aes"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"hash"
	"testing"

	"golang.org/x/crypto/md4"
)

func main() {
	// Hash([]byte("a"), "md5")
	a := utils.Init("1")
	a.SetKey([]byte("11111111"))
	// a.Hex().Hash("md5").String()
	// a.Md5().Base64Encode().String()
	// a.Md5().Base64Encode().String()
	a.DesCBCEncrypt().Hex().String()
	// fmt.Println(a)
	// c4ca4238a0b923820dcc509a6f75849b

}

func Hex(src []byte) string {
	return hex.EncodeToString(src)
}

func Hash(src []byte, tool string) string {
	var hash hash.Hash
	switch tool {
	case "md4":
		hash = md4.New()
	case "md5":
		hash = md5.New()
	case "sha1":
		hash = sha1.New()
	case "sha256":
		hash = sha256.New()
	case "sha512":
		hash = sha512.New()
	}

	hash.Write([]byte(src))
	dst := hash.Sum(nil)

	return hex.EncodeToString(dst)
}

//ECB模式解密
func ECBDecrypt(crypted, key []byte) ([]byte, error) {
	if !validKey(key) {
		return nil, fmt.Errorf("秘钥长度错误,当前传入长度为 %d", len(key))
	}
	if len(crypted) < 1 {
		return nil, fmt.Errorf("源数据长度不能为0")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	if len(crypted)%block.BlockSize() != 0 {
		return nil, fmt.Errorf("源数据长度必须是 %d 的整数倍，当前长度为：%d", block.BlockSize(), len(crypted))
	}
	var dst []byte
	tmpData := make([]byte, block.BlockSize())

	for index := 0; index < len(crypted); index += block.BlockSize() {
		block.Decrypt(tmpData, crypted[index:index+block.BlockSize()])
		dst = append(dst, tmpData...)
	}
	dst, err = PKCS5UnPadding(dst)
	if err != nil {
		return nil, err
	}
	return dst, nil
}

//ECB模式加密
func ECBEncrypt(src, key []byte) ([]byte, error) {
	if !validKey(key) {
		return nil, fmt.Errorf("秘钥长度错误, 当前传入长度为 %d", len(key))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	if len(src) < 1 {
		return nil, fmt.Errorf("源数据长度不能为0")
	}
	src = PKCS5Padding(src, block.BlockSize())
	if len(src)%block.BlockSize() != 0 {
		return nil, fmt.Errorf("源数据长度必须是 %d 的整数倍，当前长度为：%d", block.BlockSize(), len(src))
	}
	var dst []byte
	tmpData := make([]byte, block.BlockSize())
	for index := 0; index < len(src); index += block.BlockSize() {
		block.Encrypt(tmpData, src[index:index+block.BlockSize()])
		dst = append(dst, tmpData...)
	}
	return dst, nil
}

// PKCS5填充
func PKCS5Padding(ciphertext []byte, blockSize int) []byte {
	padding := blockSize - len(ciphertext)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(ciphertext, padtext...)
}

// 去除PKCS5填充
func PKCS5UnPadding(origData []byte) ([]byte, error) {
	length := len(origData)
	unpadding := int(origData[length-1])

	if length < unpadding {
		return nil, fmt.Errorf("invalid unpadding length")
	}
	return origData[:(length - unpadding)], nil
}

// 秘钥长度验证
func validKey(key []byte) bool {
	k := len(key)
	switch k {
	default:
		return false
	case 16, 24, 32:
		return true
	}
}

func TestAes(t *testing.T) {
	srcData := "hello world !"
	key := []byte("abcdabcdabcdabcdabcdabcdabcdabcd")
	//测试加密
	encData, err := ECBEncrypt([]byte(srcData), (key))
	if err != nil {
		t.Errorf(err.Error())
		return
	}
	t.Log(base64.StdEncoding.EncodeToString(encData))

	//测试解密
	decData, err := ECBDecrypt(encData, key)
	if err != nil {
		t.Errorf(err.Error())
		return
	}
	t.Log(string(decData))
}
