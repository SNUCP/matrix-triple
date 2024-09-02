package hpbfv

import "hp-bfv/rlwe"

type Ciphertext struct {
	*rlwe.Ciphertext
}

// NewCiphertext creates a new ciphertext parameterized by degree, level and scale.
func NewCiphertext(params Parameters, degree int) (ciphertext *Ciphertext) {
	return &Ciphertext{rlwe.NewCiphertext(params.Parameters, degree, params.MaxLevel())}
}

// CopyNew creates a deep copy of the receiver ciphertext and returns it.
func (ct *Ciphertext) CopyNew() *Ciphertext {
	return &Ciphertext{ct.Ciphertext.CopyNew()}
}

// MarshalBinary encodes a Ciphertext in a byte slice.
func (ct *Ciphertext) MarshalBinary() (data []byte, err error) {
	return ct.Ciphertext.MarshalBinary()
}

// UnmarshalBinary decodes a previously marshaled Ciphertext in the target Ciphertext.
func (ct *Ciphertext) UnmarshalBinary(data []byte) (err error) {
	ct.Ciphertext = new(rlwe.Ciphertext)
	return ct.Ciphertext.UnmarshalBinary(data)
}
