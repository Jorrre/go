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

func (s *SakeState) IsInitialized() bool {
	return s != nil && s.Kdk != nil && s.HmacKey != nil && s.Mode > 0
}

func (s *SakeState) AdvanceNextOdd(prf func([]byte, []byte) []byte) {
	nextOdd := s.Counter + s.Counter%2 + 1
	steps := nextOdd - s.Counter
	s.Advance(prf, steps)
}

func (s *SakeState) Advance(prf func([]byte, []byte) []byte, steps uint32) {
	for i := uint32(0); i < steps; i++ {
		s.Kdk = prf([]byte("ad"), s.Kdk)
		s.Counter += 1
	}
}

func (s *SakeState) CreateHmac(h crypto.Hash, identity []byte) ([]byte, error) {
	return s.makeHmac(h, identity, s.Counter)
}

func (s *SakeState) VerifyHmac(h crypto.Hash, identity []byte, receivedCounter uint32, receivedHmac []byte) bool {
	localHmac, err := s.makeHmac(h, identity, receivedCounter)
	if err != nil {
		return false
	}
	return hmac.Equal(localHmac, receivedHmac)
}

func (s *SakeState) makeHmac(h crypto.Hash, identity []byte, counter uint32) ([]byte, error) {
	hs := hmac.New(h.New, s.HmacKey)
	b := cryptobyte.Builder{}
	b.AddBytes(identity)
	b.AddUint32(counter)
	verifyStringBytes, err := b.Bytes()
	if err != nil {
		return nil, err
	}
	return hs.Sum(verifyStringBytes), nil
}
