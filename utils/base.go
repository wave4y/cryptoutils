// Package utils retains the historical import path and CTF helpers.
// Cryptographic operations delegate to the root cryptoutils package.
package utils

import "www.gitlablow.com/wave4y/cryptoutils"

// CryptoData is the shared implementation from the root package.
type CryptoData = cryptoutils.CryptoData

// Init creates a processing chain. Prefer cryptoutils.Init for new code.
func Init(src interface{}) *CryptoData { return cryptoutils.Init(src) }
