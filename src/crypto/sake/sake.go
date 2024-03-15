package sake

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
