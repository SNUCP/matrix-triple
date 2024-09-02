package hpbfv

import (
	"hp-bfv/rlwe"
)

type KeyGenerator interface {
	rlwe.KeyGenerator
	GenDefaultRotationKeysForRotation(sk *rlwe.SecretKey) (rks *rlwe.RotationKeySet)
	GenRotationKeysForMatMul(sk *rlwe.SecretKey, dim int) (rks *rlwe.RotationKeySet)
}

type keyGenerator struct {
	rlwe.KeyGenerator
	params Parameters
}

// GenRotationKeysForRotations generates a RotationKeySet supporting left rotations by k positions for all k in ks.
func (keygen *keyGenerator) GenRotationKeysForRotation(ks []uint64, sk *rlwe.SecretKey) (rks *rlwe.RotationKeySet) {
	galEls := make([]uint64, len(ks), len(ks)+1)
	for i, k := range ks {
		galEls[i] = keygen.params.GaloisElementForColumnRotationBy(k)
	}
	return keygen.GenRotationKeys(galEls, sk)
}

// GenRotationKeysForRotations generates a RotationKeySet supporting left rotations by k positions where k is a power of two
func (keygen *keyGenerator) GenDefaultRotationKeysForRotation(sk *rlwe.SecretKey) (rks *rlwe.RotationKeySet) {
	ks := make([]uint64, 0)
	for i := 1; i < keygen.params.Slots(); i *= 2 {
		ks = append(ks, uint64(i))
	}

	return keygen.GenRotationKeysForRotation(ks, sk)
}

// GenRotationKeysForMatMul generates a RotationKeySet supporting rotations for the matrix multiplication.
func (keygen *keyGenerator) GenRotationKeysForMatMul(sk *rlwe.SecretKey, dim int) (rks *rlwe.RotationKeySet) {
	pack := keygen.params.Slots() / dim
	if dim*pack != keygen.params.Slots() {
		panic("dim must divide the number of slots")
	}

	rks = &rlwe.RotationKeySet{Keys: make(map[uint64]*rlwe.SwitchingKey, dim)}
	ringQ := keygen.params.RingQ()
	ringP := keygen.params.RingP()
	skOut := rlwe.NewSecretKey(keygen.params.Parameters)
	for k := 0; k < keygen.params.Slots(); k += pack {
		galEl := keygen.params.GaloisElementForColumnRotationBy(uint64(k))

		ringQ.PermuteNTT(sk.Value.Q, galEl, skOut.Value.Q)
		if ringP != nil {
			ringP.PermuteNTT(sk.Value.P, galEl, skOut.Value.P)
		}

		rks.Keys[galEl] = keygen.GenSwitchingKey(skOut, sk)
	}

	return rks
}

// NewKeyGenerator creates a rlwe.KeyGenerator instance from the HP-BFV parameters.
func NewKeyGenerator(params Parameters) KeyGenerator {
	return &keyGenerator{rlwe.NewKeyGenerator(params.Parameters), params}
}
