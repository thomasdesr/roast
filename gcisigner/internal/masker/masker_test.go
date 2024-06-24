package masker

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"testing"
)

func TestNaclMaskBadInput(t *testing.T) {
	for _, tc := range [][]byte{
		nil,
		{1, 2, 3},
		make([]byte, 33),
		make([]byte, 42),
	} {
		t.Run(string(tc), func(t *testing.T) {
			res := Mask(tc, []byte{})
			if res != nil {
				t.Fatalf("expected nil, got %v", res)
			}
		},
		)
	}
}

func TestMaskRoundTrip(t *testing.T) {
	mask := make([]byte, 32)
	if _, err := rand.Read(mask); err != nil {
		panic("failed to read random bytes")
	}
	payload := []byte("hello world")
	out := Mask(mask, payload)

	{ // Debug
		t.Logf("Payload: %q", payload)
		t.Logf("Mask: %q", hex.EncodeToString(mask))
		t.Logf("Masked: %q", hex.EncodeToString(out))
	}

	rt, err := Unmask(mask, out)
	if err != nil {
		t.Fatal("failed to unmask")
	}

	{ // Debug
		t.Logf("Unmasked: %q", rt)
	}

	if !bytes.Equal(rt, payload) {
		t.Fatalf("expected empty slice, got %v", rt)
	}
}

func TestUnmask(t *testing.T) {
	mask := make([]byte, 32)
	if _, err := rand.Read(mask); err != nil {
		panic("failed to read random bytes")
	}

	bad := make([]byte, 40)
	if _, err := rand.Read(bad); err != nil {
		panic("failed to read random bytes")
	}

	rt, err := Unmask(mask, bad)
	if err == nil {
		t.Fatal("unmask should not succeed on bad data")
	}

	if rt != nil {
		t.Fatalf("expected empty slice, got %v", rt)
	}
}
