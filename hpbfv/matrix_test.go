package hpbfv_test

import (
	"fmt"
	"hp-bfv/hpbfv"
	"math/big"
	"testing"

	"hp-bfv/ring"
	"hp-bfv/utils"
)

var matParamSet = []hpbfv.ParametersLiteral{
	hpbfv.HPN14D13T128,
	hpbfv.HPN14D12T256,
	hpbfv.HPN14D11T512,
	hpbfv.HPN14D10T1024,
	hpbfv.HPN14D9T2048,
	hpbfv.HPN14D8T4096,

	hpbfv.HPN13D10T128,
	hpbfv.HPN13D9T256,
	hpbfv.HPN13D8T512,
	hpbfv.HPN13D7T1024,
}

var mulParamSet = []hpbfv.ParametersLiteral{
	hpbfv.HPN14D13T128,
	hpbfv.HPN14D12T256,
	hpbfv.HPN14D11T512,
	hpbfv.HPN14D10T1024,
	hpbfv.HPN14D9T2048,
	hpbfv.HPN14D8T4096,

	hpbfv.HPN13D10T128,
	hpbfv.HPN13D9T256,
	hpbfv.HPN13D8T512,
	hpbfv.HPN13D7T1024,
	hpbfv.HPN13D6T2048,
	hpbfv.HPN13D5T4096,

	hpbfv.PN15T128,
	hpbfv.PN16T256,
	hpbfv.PN17T512,
	hpbfv.PN18T1024,
}

func TestMatMul(t *testing.T) {
	params := hpbfv.NewParametersFromLiteral(hpbfv.HPN14D13T128)

	dims := 2
	pack := params.Slots() / dims
	M0 := make([][][]*big.Int, pack)
	M1 := make([][][]*big.Int, pack)
	MOut := make([][][]*big.Int, pack)
	for i := 0; i < pack; i++ {
		M0[i] = [][]*big.Int{
			{big.NewInt(1), big.NewInt(2)},
			{big.NewInt(3), big.NewInt(4)},
		}

		M1[i] = [][]*big.Int{
			{big.NewInt(5), big.NewInt(6)},
			{big.NewInt(7), big.NewInt(8)},
		}

		MOut[i] = [][]*big.Int{
			{big.NewInt(19), big.NewInt(22)},
			{big.NewInt(43), big.NewInt(50)},
		}
	}

	kg := hpbfv.NewKeyGenerator(params)
	sk, pk := kg.GenKeyPair()
	rlk := kg.GenRelinearizationKey(sk, 1)
	rks := kg.GenRotationKeysForMatMul(sk, dims)

	ecd := hpbfv.NewMatrixEncoder(params)
	pt0 := ecd.EncodeMatrixNew(M0, true)
	pt1 := ecd.EncodeMatrixNew(M1, false)

	enc := hpbfv.NewMatrixEncryptor(params, pk, sk)
	ct0 := enc.EncryptNew(pt0)
	ct1 := enc.EncryptNew(pt1)

	eval := hpbfv.NewMatrixEvaluator(params, rlk, rks)
	ctOut := eval.MulNew(ct0, ct1)

	ptOut := enc.DecryptNew(ctOut)
	MOutTest := ecd.DecodeMatrixNew(ptOut)

	for i := 0; i < pack; i++ {
		for j := 0; j < dims; j++ {
			for k := 0; k < dims; k++ {
				if MOutTest[i][j][k].Cmp(MOut[i][j][k]) != 0 {
					t.Errorf("expected %v, got %v", MOut[i][j][k], MOutTest[i][j][k])
				}
			}
		}
	}
}

func BenchmarkMatMul(b *testing.B) {
	dim := 128
	prng, _ := utils.NewPRNG()

	for _, pl := range matParamSet {
		params := hpbfv.NewParametersFromLiteral(pl)

		us := ring.NewUniformSampler(prng, params.RingQ())

		ctA := hpbfv.NewMatrixCiphertext(params, dim, true)
		ctB := hpbfv.NewMatrixCiphertext(params, dim, false)
		ctC := hpbfv.NewMatrixCiphertext(params, dim, true)

		for i := range ctA.Value {
			us.Read(ctA.Value[i].Value[0])
			us.Read(ctA.Value[i].Value[1])
		}
		for i := range ctB.Value {
			us.Read(ctB.Value[i].Value[0])
			us.Read(ctB.Value[i].Value[1])
		}

		kg := hpbfv.NewKeyGenerator(params)
		sk := kg.GenSecretKey()
		rlk := kg.GenRelinearizationKey(sk, 1)
		rks := kg.GenRotationKeysForMatMul(sk, dim)

		eval := hpbfv.NewMatrixEvaluator(params, rlk, rks)

		logT := params.T().BitLen()

		b.Run(fmt.Sprintf("MatMul/N=%v/T=%v/Pack=%v", params.LogN(), logT, ctA.Pack), func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				eval.Mul(ctA, ctB, ctC)
			}
		})
	}
}

func BenchmarkMatMulAuth(b *testing.B) {

	params := hpbfv.NewParametersFromLiteral(hpbfv.HPN14D13T128)
	prng, _ := utils.NewPRNG()
	us := ring.NewUniformSampler(prng, params.RingQ())

	ctMAC := hpbfv.NewCiphertext(params, 1)
	us.Read(ctMAC.Value[0])
	us.Read(ctMAC.Value[1])

	kg := hpbfv.NewKeyGenerator(params)
	sk := kg.GenSecretKey()
	rlk := kg.GenRelinearizationKey(sk, 1)

	cEval := hpbfv.NewEvaluator(params)

	for _, dim := range []int{128, 256, 512} {
		ctA := hpbfv.NewMatrixCiphertext(params, dim, true)
		ctB := hpbfv.NewMatrixCiphertext(params, dim, false)
		ctC := hpbfv.NewMatrixCiphertext(params, dim, true)

		for i := range ctA.Value {
			us.Read(ctA.Value[i].Value[0])
			us.Read(ctA.Value[i].Value[1])
		}
		for i := range ctB.Value {
			us.Read(ctB.Value[i].Value[0])
			us.Read(ctB.Value[i].Value[1])
		}

		rks := kg.GenRotationKeysForMatMul(sk, dim)

		eval := hpbfv.NewMatrixEvaluator(params, rlk, rks)

		b.Run(fmt.Sprintf("MatMulAuth/d=%v", dim), func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				eval.Mul(ctA, ctB, ctC)
				for i := range ctC.Value {
					cEval.MulAndRelin(ctC.Value[i], ctMAC, rlk, ctC.Value[i])
				}
			}
		})
	}
}

func BenchmarkMul(b *testing.B) {
	prng, _ := utils.NewPRNG()

	for _, pl := range mulParamSet {
		params := hpbfv.NewParametersFromLiteral(pl)

		us := ring.NewUniformSampler(prng, params.RingQ())

		ct0 := hpbfv.NewCiphertext(params, 1)
		ct1 := hpbfv.NewCiphertext(params, 1)
		ctOut := hpbfv.NewCiphertext(params, 1)

		for i := 0; i < 2; i++ {
			us.Read(ct0.Value[i])
			us.Read(ct1.Value[i])
		}

		kg := hpbfv.NewKeyGenerator(params)
		sk := kg.GenSecretKey()
		rlk := kg.GenRelinearizationKey(sk, 1)

		eval := hpbfv.NewEvaluator(params)

		logT := params.T().BitLen()
		var benchName string
		if params.D() == uint64(params.N()) {
			benchName = fmt.Sprintf("MulOriginal/N=%v/T=%v", params.LogN(), logT)
		} else {
			benchName = fmt.Sprintf("Mul/N=%v/T=%v/D=%v", params.LogN(), logT, params.D())
		}

		b.Run(benchName, func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				eval.MulAndRelin(ct0, ct1, rlk, ctOut)
			}
		})
	}
}
