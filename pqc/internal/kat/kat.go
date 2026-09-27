// Package kat is a test-only loader for the preserved NIST ACVP samples.
package kat

import (
	"compress/gzip"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

type Hex []byte

func (h *Hex) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}
	data, err := hex.DecodeString(s)
	*h = data
	return err
}

type Values struct {
	TcID                                                   int `json:"tcId"`
	D, Z, Seed, SkSeed, SkPrf, PkSeed                      Hex
	Ek, Dk, Pk, Sk, M, K, C                                Hex
	Message, Signature, Rnd, Context, AdditionalRandomness Hex
	TestPassed                                             bool
}
type Case struct {
	Operation, Parameter, TestType string
	TgID                           int
	Deterministic                  bool
	Pk, Dk                         Hex
	Input, Output                  Values
}

func Load(t *testing.T, family string) []Case {
	t.Helper()
	_, file, _, _ := runtime.Caller(0)
	f, err := os.Open(filepath.Join(filepath.Dir(file), "..", "..", "testdata", family+".json.gz"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		t.Fatal(err)
	}
	defer gz.Close()
	var cases []Case
	if err := json.NewDecoder(gz).Decode(&cases); err != nil {
		t.Fatal(err)
	}
	return cases
}
