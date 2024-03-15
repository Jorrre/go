package sake

import (
	"crypto"
	"crypto/hmac"
	"golang.org/x/crypto/cryptobyte"
)

func AdvanceNextOdd(kdk *[]byte, counter *uint32, prf func([]byte, []byte) []byte) {
	steps := *counter + *counter%2 + 1
	Advance(kdk, counter, prf, steps)
}

func Advance(kdk *[]byte, counter *uint32, prf func([]byte, []byte) []byte, steps uint32) {
	for i := uint32(0); i < steps; i++ {
		*kdk = prf([]byte("ad"), *kdk)
		*counter += 1
	}
}

func CreateSakeVerify(h crypto.Hash, hmacKey []byte, identity []byte, counter uint32) ([]byte, error) {
	hs := hmac.New(h.New, hmacKey)
	b := cryptobyte.Builder{}
	b.AddBytes(identity)
	b.AddUint32(counter)
	verifyStringBytes, err := b.Bytes()
	if err != nil {
		return nil, err
	}
	return hs.Sum(verifyStringBytes), nil
}

func Verify(h crypto.Hash, hmacKey []byte, identity []byte, counter uint32, receivedVerify []byte) bool {
	localVerify, err := CreateSakeVerify(h, hmacKey, identity, counter)
	if err != nil {
		return false
	}
	return hmac.Equal(localVerify, receivedVerify)
}
