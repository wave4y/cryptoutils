package cryptoutils

import "fmt"

type CryptoData struct {
	data  []byte
	raw   []byte
	first bool
	key   []byte
}

func Init(src interface{}) *CryptoData {
	var data []byte
	switch src := src.(type) {
	case string:
		data = []byte(src)
	case []byte:
		data = src
	}

	return &CryptoData{
		data:  data,
		raw:   data,
		first: true,
		key:   []byte(""),
	}
}

func (p *CryptoData) SetKey(key []byte) {
	p.key = key
}

func (p *CryptoData) String() string {
	p.checkFirst()

	p.first = true
	fmt.Printf("%s\n", p.data)
	return string(p.data)
}

func (p *CryptoData) checkFirst() {
	if p.first {
		p.data = p.raw
		p.first = false
	}
}
