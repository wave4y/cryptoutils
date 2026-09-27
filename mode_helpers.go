package cryptoutils

// These convenience methods use the same explicit IV and padding conventions as
// BlockEncrypt and BlockDecrypt. The raw modes do not provide authentication.
func (p *CryptoData) AESCBCEncrypt(iv []byte) *CryptoData     { return p.BlockEncrypt("aes", "cbc", iv) }
func (p *CryptoData) AESCBCDecrypt(iv []byte) *CryptoData     { return p.BlockDecrypt("aes", "cbc", iv) }
func (p *CryptoData) AESCTREncrypt(iv []byte) *CryptoData     { return p.BlockEncrypt("aes", "ctr", iv) }
func (p *CryptoData) AESCTRDecrypt(iv []byte) *CryptoData     { return p.BlockDecrypt("aes", "ctr", iv) }
func (p *CryptoData) AESCFBEncrypt(iv []byte) *CryptoData     { return p.BlockEncrypt("aes", "cfb", iv) }
func (p *CryptoData) AESCFBDecrypt(iv []byte) *CryptoData     { return p.BlockDecrypt("aes", "cfb", iv) }
func (p *CryptoData) AESOFBEncrypt(iv []byte) *CryptoData     { return p.BlockEncrypt("aes", "ofb", iv) }
func (p *CryptoData) AESOFBDecrypt(iv []byte) *CryptoData     { return p.BlockDecrypt("aes", "ofb", iv) }
func (p *CryptoData) AESECBEncrypt() *CryptoData              { return p.BlockEncrypt("aes", "ecb", nil) }
func (p *CryptoData) AESECBDecrypt() *CryptoData              { return p.BlockDecrypt("aes", "ecb", nil) }
func (p *CryptoData) AESCCMEncrypt(aad []byte) *CryptoData    { return p.AEADEncrypt("aes-ccm", aad) }
func (p *CryptoData) AESCCMDecrypt(aad []byte) *CryptoData    { return p.AEADDecrypt("aes-ccm", aad) }
func (p *CryptoData) AESXTSEncrypt(sector uint64) *CryptoData { return p.XTSEncrypt("aes", sector) }
func (p *CryptoData) AESXTSDecrypt(sector uint64) *CryptoData { return p.XTSDecrypt("aes", sector) }
func (p *CryptoData) SM4CBCEncrypt(iv []byte) *CryptoData     { return p.BlockEncrypt("sm4", "cbc", iv) }
func (p *CryptoData) SM4CBCDecrypt(iv []byte) *CryptoData     { return p.BlockDecrypt("sm4", "cbc", iv) }
func (p *CryptoData) SM4CTREncrypt(iv []byte) *CryptoData     { return p.BlockEncrypt("sm4", "ctr", iv) }
func (p *CryptoData) SM4CTRDecrypt(iv []byte) *CryptoData     { return p.BlockDecrypt("sm4", "ctr", iv) }
func (p *CryptoData) SM4CFBEncrypt(iv []byte) *CryptoData     { return p.BlockEncrypt("sm4", "cfb", iv) }
func (p *CryptoData) SM4CFBDecrypt(iv []byte) *CryptoData     { return p.BlockDecrypt("sm4", "cfb", iv) }
func (p *CryptoData) SM4OFBEncrypt(iv []byte) *CryptoData     { return p.BlockEncrypt("sm4", "ofb", iv) }
func (p *CryptoData) SM4OFBDecrypt(iv []byte) *CryptoData     { return p.BlockDecrypt("sm4", "ofb", iv) }
func (p *CryptoData) SM4ECBEncrypt() *CryptoData              { return p.BlockEncrypt("sm4", "ecb", nil) }
func (p *CryptoData) SM4ECBDecrypt() *CryptoData              { return p.BlockDecrypt("sm4", "ecb", nil) }
func (p *CryptoData) SM4CCMEncrypt(aad []byte) *CryptoData    { return p.AEADEncrypt("sm4-ccm", aad) }
func (p *CryptoData) SM4CCMDecrypt(aad []byte) *CryptoData    { return p.AEADDecrypt("sm4-ccm", aad) }
