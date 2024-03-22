package sake

import (
	"crypto"
	"crypto/hmac"
	"golang.org/x/crypto/cryptobyte"
)

const (
	LP1 uint8 = 1
	LP2 uint8 = 2
	LP3 uint8 = 3
)

type SakeState struct {
	Mode    uint8
	Kdk     []byte
	Counter uint32
	HmacKey []byte
}

type sakeMode struct {
	id            uint8
	newRunAdvance func(kdk *[]byte, counter *uint32, prf func([]byte, []byte) []byte)
}

var sakeModes = []*sakeMode{
	{LP2, AdvanceNextOdd},
}

func sakeModeById(id uint8) *sakeMode {
	for _, sakeMode := range sakeModes {
		if sakeMode.id == id {
			return sakeMode
		}
	}
	return nil
}

func (s *SakeState) IsInitialized() bool {
	return s != nil && s.Kdk != nil && s.HmacKey != nil && s.Mode > 0
}

func AdvanceNextOdd(kdk *[]byte, counter *uint32, prf func([]byte, []byte) []byte) {
	nextOdd := *counter + *counter%2 + 1
	steps := nextOdd - *counter
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
