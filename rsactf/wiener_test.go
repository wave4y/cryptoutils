package rsactf_test

import (
	"context"
	"errors"
	"math/big"
	"testing"
	"time"

	"github.com/wave4y/cryptoutils/rsactf"
)

func TestWienerBudget(t *testing.T) {
	// p=239, q=379, phi=89964, d=5, e=17993. The first two
	// convergents of e/n are 0/1 and 1/5, so both terms count.
	for _, budget := range []uint64{0, 1} {
		factor, err := rsactf.Wiener(integer(90581), integer(17993), budget)
		if factor != nil || !errors.Is(err, rsactf.ErrNoResult) {
			t.Fatalf("budget %d: got (%v, %v), want no result", budget, factor, err)
		}
	}
	for _, budget := range []uint64{2, 100, ^uint64(0)} {
		factor, err := rsactf.Wiener(integer(90581), integer(17993), budget)
		requireInteger(t, factor, err, 239)
	}
	// The implementation does not assume the public exponent is below n.
	factor, err := rsactf.Wiener(integer(90581), integer(107957), 100)
	requireInteger(t, factor, err, 239)
}

func TestWienerRejectsInvalidInputs(t *testing.T) {
	for _, pair := range [][2]*big.Int{
		{nil, integer(17993)}, {integer(90581), nil},
		{integer(-1), integer(17993)}, {integer(0), integer(17993)}, {integer(1), integer(17993)},
		{integer(90581), integer(-1)}, {integer(90581), integer(0)}, {integer(90581), integer(1)},
	} {
		for _, budget := range []uint64{0, 100} {
			factor, err := rsactf.Wiener(pair[0], pair[1], budget)
			if factor != nil || !errors.Is(err, rsactf.ErrInvalidInput) {
				t.Fatalf("n=%v e=%v budget=%d: (%v, %v)", pair[0], pair[1], budget, factor, err)
			}
		}
	}
}

func TestWienerNoResult(t *testing.T) {
	for _, tc := range []struct {
		name string
		n, e int64
	}{
		{"ordinary key", 3233, 17},
		{"noninvertible exponent", 90581, 17994},
		{"prime modulus", 101, 101},
		{"square with plausible phi", 121, 101},
		{"composite factors with plausible phi", 225, 193},
	} {
		t.Run(tc.name, func(t *testing.T) {
			factor, err := rsactf.Wiener(integer(tc.n), integer(tc.e), ^uint64(0))
			if factor != nil || !errors.Is(err, rsactf.ErrNoResult) {
				t.Fatalf("got (%v, %v), want no result", factor, err)
			}
		})
	}
}

func TestWienerSmallPrivateExponents(t *testing.T) {
	for _, pair := range [][2]int64{{101, 113}, {239, 379}, {1009, 1013}, {10007, 10009}} {
		n := integer(pair[0] * pair[1])
		phi := integer((pair[0] - 1) * (pair[1] - 1))
		for _, d := range []int64{3, 5, 7} {
			// These balanced primes and 81*d^4 < n satisfy the classical
			// sufficient condition d < n^(1/4)/3, without floating point.
			if 81*d*d*d*d >= n.Int64() {
				continue
			}
			e := new(big.Int).ModInverse(integer(d), phi)
			if e == nil {
				continue
			}
			p, err := rsactf.Wiener(n, e, 100)
			if err != nil || p == nil || p.Int64() != pair[0] {
				t.Fatalf("p=%d q=%d d=%d: got (%v, %v)", pair[0], pair[1], d, p, err)
			}
		}
	}
}

func TestWienerInputOwnership(t *testing.T) {
	n, e := integer(90581), integer(17993)
	factor, err := rsactf.Wiener(n, e, 100)
	requireInteger(t, factor, err, 239)
	factor.SetInt64(0)
	if n.Int64() != 90581 || e.Int64() != 17993 {
		t.Fatal("a returned factor aliases an input, or the search changed its inputs")
	}
	// Two arguments may share one big.Int without changing its value.
	shared := integer(90581)
	_, err = rsactf.Wiener(shared, shared, 100)
	if !errors.Is(err, rsactf.ErrNoResult) || shared.Int64() != 90581 {
		t.Fatalf("shared arguments: n=e=%v, err=%v", shared, err)
	}
}

func TestWienerContext(t *testing.T) {
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	expired, cleanup := context.WithDeadline(context.Background(), time.Unix(1, 0))
	defer cleanup()
	for _, tc := range []struct {
		ctx  context.Context
		want error
	}{
		{nil, rsactf.ErrInvalidInput},
		{canceled, context.Canceled},
		{expired, context.DeadlineExceeded},
	} {
		factor, err := rsactf.WienerContext(tc.ctx, integer(90581), integer(17993), 100)
		if factor != nil || !errors.Is(err, tc.want) {
			t.Fatalf("got (%v, %v), want (nil, %v)", factor, err, tc.want)
		}
	}
	factor, err := rsactf.WienerContext(context.Background(), integer(90581), integer(17993), 2)
	requireInteger(t, factor, err, 239)
}

// Cancel at a deterministic checkpoint, including after candidate validation,
// so cancellation tests do not rely on timing or goroutine scheduling.
type wienerCancelAfterChecks struct {
	context.Context
	cancel    context.CancelFunc
	remaining int
}

func (c *wienerCancelAfterChecks) Err() error {
	c.remaining--
	if c.remaining == 0 {
		c.cancel()
	}
	return c.Context.Err()
}

func TestWienerCancellationDuringWork(t *testing.T) {
	for _, checks := range []int{2, 4, 6, 7} {
		parent, cancel := context.WithCancel(context.Background())
		ctx := &wienerCancelAfterChecks{Context: parent, cancel: cancel, remaining: checks}
		n, e := integer(90581), integer(17993)
		factor, err := rsactf.WienerContext(ctx, n, e, 100)
		cancel()
		if factor != nil || !errors.Is(err, context.Canceled) {
			t.Fatalf("checkpoint %d: got (%v, %v), want cancellation", checks, factor, err)
		}
		if n.Int64() != 90581 || e.Int64() != 17993 {
			t.Fatal("cancellation changed an input")
		}
	}
}

// Numerical fixtures from RsaCtfTool examples at commit
// fb8532a54227b61f99277bd09483a3570c02c8f8; no attack implementation is reused.
// https://github.com/RsaCtfTool/RsaCtfTool/tree/fb8532a54227b61f99277bd09483a3570c02c8f8/examples
func TestWienerRsaCtfToolFixtures(t *testing.T) {
	cases := []struct{ name, n, e string }{
		{"boneh_durfee", "136925867715334350539351541819374303153581861883077425871381479619256902280896182751175418274848819117804106313526390171733172646719203781502341411544996240718046559322020330755493739123717974336861438650061159088512867158495809372652057009979517497499951599965613535967213529497308200114836792389883404448987", "17742461742896634972201474241931685701682825423273435469196581493593083245061146905518481601646582623355393811189032402488804067701439209191772750727581718922909269638936474927145555944487152988216781157681122522177270474504549932191814852246849976334482284151493985991827502940015843682072459462031659332887"},
		{"wiener_wiener_cipher", "3334856810184677477844358144018917794041731190055839506761047725196006094980863695382177363193369966486016701249215142483636637554021814543035830546215989929795663440797135714052529156584121356430820344157690550828800881814240591307966102200317439798025514933024378636034699031813537269957366107757164860989844073107586429425720904855051982116041375607063348284181020075517929415641544289763746613008111428479297057733166557625147336147566880214355650641577166264521190299115885380737405565001610566944363859489100969586274685083957891857940299867778179224315829434940724792203814646820239647654928926010057013368458245514278044491268911004184046810260941759997123197041098733517706050844547145597277455472453774614055218254132399751743258899881787475545751497375960922131268299479552529031035888108780949909103896592757431124458704783417755010801978390551651313047542712508524793275560368174745062513752629553237925010211952156417038790055587317248535295143994247940211251656493513423704508343198542105407781884990875230425908547394673929549851133924331163825482577078961944622191862486639441372854700487426887512910454786510827672456213611323195410584868699053780747730586864834422625763265388125692936999503906754918551854172173689", "2886742484284236738106774553791894046416444145459517541766656102330583532154902136604981835389880876713510845417271964019204206949327057151814809422028064218677671539780756790073245011971779691151399771785594074102959490942011855461922052373256869112586069827237757677531152193793922244290357631084923476294942724769982806739137984440930721076461131445531563983299231761780264950983814074640237982898488917656165224244195387250924608815967348988209556714420639312419361130926877862538413221196848322559474276711620086565581403677553882228263027399722889281656046918967381048807623526364266143600256088104112918099637085367138980880401801929864949191436201487350316442963262388421086044955615708039631976078142986495395413372609466947411695520320289903706466828341807884432581092036782685314853874294858647103670051043525755503755113156275596704174274371810869392692475528911042436194087115337615374222449956292870848959480797114952026583740853480852705976157805343363101525183964560440988129944984991815645605643759337280581457184559678726060653232062032958445566260119329244132071683732161836203152982640205805727156468285180704488652033448482014914282137473931519173301689100603078652134608031181394091081450726382793079353630028427"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			n, ok := new(big.Int).SetString(tc.n, 10)
			if !ok {
				t.Fatal("invalid modulus fixture")
			}
			e, ok := new(big.Int).SetString(tc.e, 10)
			if !ok {
				t.Fatal("invalid exponent fixture")
			}
			p, err := rsactf.Wiener(n, e, 10000)
			requireFactor(t, n, p, err)
			q := new(big.Int).Quo(n, p)
			if p.Cmp(q) == 0 || !p.ProbablyPrime(32) || !q.ProbablyPrime(32) {
				t.Fatal("recovered factors are not distinct probable primes")
			}
			phi := new(big.Int).Mul(new(big.Int).Sub(p, integer(1)), new(big.Int).Sub(q, integer(1)))
			d := new(big.Int).ModInverse(e, phi)
			if d == nil {
				t.Fatal("exponent is not invertible modulo recovered phi")
			}
			// Independently validate the recovered key against messages that
			// include zero and multiples of each recovered prime.
			for _, m := range []*big.Int{integer(0), integer(42), p, q, new(big.Int).Sub(n, integer(1))} {
				ciphertext := new(big.Int).Exp(m, e, n)
				plaintext := new(big.Int).Exp(ciphertext, d, n)
				if plaintext.Cmp(m) != 0 {
					t.Fatal("recovered key fails a raw RSA round trip")
				}
			}
		})
	}
}
