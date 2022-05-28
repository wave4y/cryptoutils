package cryptoutils

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
)

// https://blog.csdn.net/zhangxing52077/article/details/89204861
func aaa() {

	privateKey, err := rsa.GenerateKey(rand.Reader, 4096)

	if err != nil {
		return
	}
	derStream := x509.MarshalPKCS1PrivateKey(privateKey)
	priBlock := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: derStream,
	}
	fmt.Printf("=======私钥文件内容=========%v", string(pem.EncodeToMemory(priBlock)))

	publicKey := &privateKey.PublicKey
	derPkix, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return
	}
	publicBlock := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: derPkix,
	}

	fmt.Printf("=======公钥文件内容=========%v", string(pem.EncodeToMemory(publicBlock)))

	if err != nil {
		return
	}

}

/*
-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAzDg066L+EY7R4O/nWEcNPKMXV37vnRnA4zAqayuqbEE1L+qZ
/IwzWU+V2SZR3UnjT25TRNldtADPlPP9m0AgppcR34u883OKmFpyKaDTzzJu08wP
TKh2TMsseWfrIqvtfI8PJfdwnitYWqoJpruOf28iPHUFXBB6j2dg7LGwMyn3/bvC
/+gCtIq++ySEQkLVnd7q5CciLRNleqUUf3myzO1cnx5E9KIs5pbq0YAwQSRZW6jV
w5LMTle3j4o8dIy1moKEAOFz+1oG9gpRRgy3k85oQDaEiue61ufiGu1bfDruAjIC
IackbZJsGjUObBblSAazWoEwxVJdg2jRCJwkaQIDAQABAoIBAAfCUvBo/vI31O2Q
799Aw9X79FUUs5HqepOnLtVnkVAPoi+x4CviP8ky5uSbOh0IQ6Su8mb5Q0Alj71/
D7GoXBU4RCuUKZeuWiOzvAas359NsTxG0oX9GJGOXqA2PI7SrXFAFjlBD3xS9UZs
k3VMRvu8gzZ807lNvvpX2SzlC2bGLgRr1jwdlhV9Lfxk46UOOwISwTMyqYDKQd4l
giGj3Vd7/C1Ubyxs1MeFL9Cy3ipyI4fliThDP1S24TTsbUQZgUuiFsY7c/7A/uur
fHZ1RFdowSAtbDzmff4TVBqzJBAkHlYouw/drX5QT5WacnIQUT28JFPw06orOhxp
cNRTMqECgYEA1L22kH8xm7cdtzRZKgRLbtiHoA8WHbMROg+/4Ou2e/+6CfSxv1Ma
U5I+i71OMoDoz59XqqnydulENcHsF7tdI3yXPgJBRTOHKrXmqomS7j2iEIdpTagj
mjE7ZQYBupq27kujQ4dSxDrlbKysOiSUXifdpPgewQJ1O5fhIyVJ/U0CgYEA9b7n
hSr8f8J86tPdPNf9kEZ/DVslgfZvSZpArMbB4R+5bHBgIgV2c+vkd/iSVtsjRueX
/kuLZuBtk+sPN2GC6Ppo3eqoLbstx2oLX81dVA/xesmbNJc6RMdCkxSWN3hsgkE+
OHnD45dzbxb21Qyfl5Hu28rtelnnlyl37KB9pY0CgYEAvhsZvV4sMn4cK863rvhP
gCo2aC2TEc8mob/ZM2DvnTcURDlJbTMR34RcJ/tumWrgoEg/yt47MU+aCH/WPg7M
WB3J+TuCoBg/vUb3bYWqqwKghCy9SQvrZKqB7PDFMr92oNMuffW7XGdVBRv4e6yc
eNcfFYAz2z4bDLnYEdQMnjECgYAe6LMQEdcObrTtiFZUV8phwiwqzuMJ1KgstsUZ
tioembHlzMCapts+O1ZSLKajXA601V5NsszG1MWTjEYurgocKZrVBrW+gsOASHtD
wn3Rm+vAiOkHlVnT2sgp3bYDJhdnzrL3wYD8+EihmV7UbzEHjGhhpsV11ScG4UVf
MtR65QKBgDmNVkhtsJsQ/dvQPw9oZdrycA38qZ6cozPPE9QCQowcOZ1v5RO4eewg
UkyxdjAYT7a6E0XUrqwBxb0rMEZZmZWS+m6dPCD1UZnP9/Lq1xHPD0I8FRDRpxcW
Ds5M3Z8V1pKjfPK4M7upMuw9vRpC26tJYIS51jmy8hT40GXGHqJp
-----END RSA PRIVATE KEY-----


-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAzDg066L+EY7R4O/nWEcN
PKMXV37vnRnA4zAqayuqbEE1L+qZ/IwzWU+V2SZR3UnjT25TRNldtADPlPP9m0Ag
ppcR34u883OKmFpyKaDTzzJu08wPTKh2TMsseWfrIqvtfI8PJfdwnitYWqoJpruO
f28iPHUFXBB6j2dg7LGwMyn3/bvC/+gCtIq++ySEQkLVnd7q5CciLRNleqUUf3my
zO1cnx5E9KIs5pbq0YAwQSRZW6jVw5LMTle3j4o8dIy1moKEAOFz+1oG9gpRRgy3
k85oQDaEiue61ufiGu1bfDruAjICIackbZJsGjUObBblSAazWoEwxVJdg2jRCJwk
aQIDAQAB
-----END PUBLIC KEY-----

*/
