// Masker exists to provide a simple way to obfuscate data in a way that will
// make it much harder for someone using the gcisigner to accidentally bypass
// the SigV4 signed message verification.
package masker

import (
	"crypto/rand"
	"errors"
	"io"

	"golang.org/x/crypto/nacl/secretbox"
)

// Mask is designed to obfuscate data to make using unverified data less likely.
func Mask(mask []byte, data []byte) []byte {
	if len(mask) != 32 {
		return nil
	}

	var nonce [24]byte
	if _, err := io.ReadFull(rand.Reader, nonce[:]); err != nil {
		panic(err)
	}

	return secretbox.Seal(nonce[:], data, &nonce, (*[32]byte)(mask))
}

// Unmask unmasks data masked with naclMask
func Unmask(mask []byte, data []byte) ([]byte, error) {
	if len(mask) != 32 {
		return nil, errors.New("invalid mask")
	}

	var nonce [24]byte
	copy(nonce[:], data[:24])

	resp, ok := secretbox.Open(nil, data[24:], &nonce, (*[32]byte)(mask))
	if !ok {
		return nil, errors.New("failed to unmask")
	}
	return resp, nil
}
