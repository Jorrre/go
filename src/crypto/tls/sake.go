package tls

import (
	"crypto"
	"crypto/hmac"
	"strconv"
)

const (
	lp2 uint8 = 2
)

type lpState struct {
	mode    uint8
	kdk     []byte
	counter uint32
	hmacKey []byte
}

func (l *lpState) advanceNextOdd(prf func([]byte, []byte) []byte) {
	nextOdd := l.counter + l.counter%2 + 1
	steps := nextOdd - l.counter
	l.advance(prf, steps)
}

func (l *lpState) advance(prf func([]byte, []byte) []byte, steps uint32) {
	for i := uint32(0); i < steps; i++ {
		l.kdk = prf([]byte("ad"), l.kdk)
		l.counter += 1
	}
}

func (l *lpState) createHmac(h crypto.Hash, identity string) []byte {
	return l.makeHmac(h, identity, l.counter)
}

func (l *lpState) verifyHmac(h crypto.Hash, identity string, receivedCounter uint32, receivedHmac []byte) bool {
	localHmac := l.makeHmac(h, identity, receivedCounter)
	return hmac.Equal(localHmac, receivedHmac)
}

func (l *lpState) makeHmac(h crypto.Hash, identity string, counter uint32) []byte {
	hs := hmac.New(h.New, l.hmacKey)
	verifyString := identity + strconv.Itoa(int(counter))
	return hs.Sum([]byte(verifyString))
}
