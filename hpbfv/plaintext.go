package hpbfv

import (
	"math/big"

	"hp-bfv/rlwe"
)

// Plaintext is a Element with only one Poly. It represents a Plaintext element in R_q that is the
// result of scaling the corresponding element of R_t up by Q/t. This is a generic all-purpose type
// of plaintext: it will work with for all operations. It is however less compact than PlaintextRingT
// and will result in less efficient Ciphert-Plaintext multiplication than PlaintextMul. See bfv/encoder.go
// for more information on plaintext types.
type Plaintext struct {
	*rlwe.Plaintext
}

// NewPlaintext creates and allocates a new plaintext in RingQ (multiple moduli of Q).
// The plaintext will be in RingQ and scaled by Q/t.
// Slower encoding and larger plaintext size
func NewPlaintext(params Parameters) *Plaintext {
	plaintext := &Plaintext{rlwe.NewPlaintext(params.Parameters, params.MaxLevel())}
	return plaintext
}

type Message struct {
	Value []*big.Int
}

func NewMessage(params Parameters) *Message {
	msg := new(Message)
	msg.Value = make([]*big.Int, params.Slots())

	for i := 0; i < params.Slots(); i++ {
		msg.Value[i] = big.NewInt(0)
	}

	return msg
}
