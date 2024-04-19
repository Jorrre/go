package sake

import (
	"crypto"
	"crypto/hmac"
	"strconv"
)

const (
	LP2 uint8 = 2
)

type SakeState struct {
	Mode    uint8
	Kdk     []byte
	Counter uint32
	HmacKey []byte
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

func (s *SakeState) CreateHmac(h crypto.Hash, identity string) []byte {
	return s.makeHmac(h, identity, s.Counter)
}

func (s *SakeState) VerifyHmac(h crypto.Hash, identity string, receivedCounter uint32, receivedHmac []byte) bool {
	localHmac := s.makeHmac(h, identity, receivedCounter)
	return hmac.Equal(localHmac, receivedHmac)
}

func (s *SakeState) makeHmac(h crypto.Hash, identity string, counter uint32) []byte {
	hs := hmac.New(h.New, s.HmacKey)
	verifyString := identity + strconv.Itoa(int(counter))
	return hs.Sum([]byte(verifyString))
}
