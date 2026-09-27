package sm2

import (
	"bytes"
	"testing"
)

// Interoperability fixture from emmansun/gmsm v0.29.8 sm2/sm2_keyexchange_test.go.
// Only the fixed input/output data is reproduced; no runtime dependency is used.
func TestExchangeKnownKey(t *testing.T) {
	parse := func(s string) *PrivateKey {
		k, err := NewPrivateKey(decode(s))
		if err != nil {
			t.Fatal(err)
		}
		return k
	}
	a := parse("e04c3fd77408b56a648ad439f673511a2ae248def3bab26bdfc9cdbd0ae9607e")
	ar := parse("6fe0bac5b09d3ab10f724638811c34464790520e4604e71e6cb0e5310623b5b1")
	b := parse("7a1136f60d2c5531447e5a3093078c2a505abf74f33aefed927ac0a5b27e7dd7")
	br := parse("d0233bdbb0b8a7bfe1aab66132ef06fc4efaedd5d5000692bc21185242a31f6f")
	ra, err := Exchange(a, ar, &b.PublicKey, &br.PublicKey, []byte("Alice"), []byte("Bob"), true, 48)
	if err != nil {
		t.Fatal(err)
	}
	rb, err := Exchange(b, br, &a.PublicKey, &ar.PublicKey, []byte("Bob"), []byte("Alice"), false, 48)
	if err != nil {
		t.Fatal(err)
	}
	want := decode("1ad809ebc56ddda532020c352e1e60b121ebeb7b4e632db4dd90a362cf844f8bba85140e30984ddb581199bf5a9dda22")
	ka, err := ra.Confirm(rb.Confirmation())
	if err != nil || !bytes.Equal(ka, want) {
		t.Fatalf("initiator %x %v", ka, err)
	}
	kb, err := rb.Confirm(ra.Confirmation())
	if err != nil || !bytes.Equal(kb, want) {
		t.Fatalf("responder %x %v", kb, err)
	}
}
