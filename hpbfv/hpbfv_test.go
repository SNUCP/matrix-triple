package hpbfv

import (
	/*
		  "encoding/json"
			"flag"
			"runtime"

			"github.com/stretchr/testify/require"
	*/

	"fmt"
	"testing"

	"hp-bfv/ring"
	"hp-bfv/rlwe"
	"hp-bfv/utils"

	"github.com/stretchr/testify/assert"
)

type testContext struct {
	params    Parameters
	ringQ     *ring.Ring
	prng      utils.PRNG
	uSampler  *ring.UniformSampler
	kgen      KeyGenerator
	sk        *rlwe.SecretKey
	pk        *rlwe.PublicKey
	rlk       *rlwe.RelinearizationKey
	rtks      *rlwe.RotationKeySet
	encoder   *Encoder
	decoder   *Decoder
	encryptor *Encryptor
	decryptor *Decryptor
	eval      *Evaluator
}

func testString(opname string, p Parameters) string {
	return fmt.Sprintf("%s/LogN=%d/logQ=%d/alpha=%d/beta=%d", opname, p.LogN(), p.LogQP(), p.PCount(), p.DecompRNS(p.QCount()-1, p.PCount()-1))
}

func genTestParams(params Parameters) (testctx *testContext, err error) {

	testctx = new(testContext)
	testctx.params = params

	if testctx.prng, err = utils.NewPRNG(); err != nil {
		return nil, err
	}

	testctx.ringQ = params.RingQ()

	testctx.uSampler = ring.NewUniformSampler(testctx.prng, testctx.ringQ)

	testctx.kgen = NewKeyGenerator(testctx.params)

	testctx.sk, testctx.pk = testctx.kgen.GenKeyPair()

	testctx.rlk = testctx.kgen.GenRelinearizationKey(testctx.sk, 1)
	testctx.rtks = testctx.kgen.GenDefaultRotationKeysForRotation(testctx.sk)

	testctx.encoder = NewEncoder(testctx.params)
	testctx.decoder = NewDecoder(testctx.params)

	testctx.encryptor = NewEncryptor(testctx.params, testctx.pk)
	testctx.decryptor = NewDecryptor(testctx.params, testctx.sk)

	testctx.eval = NewEvaluator(testctx.params)

	return

}

func genTestVectors(testctx *testContext) (msg *Message) {
	params := testctx.params
	coeffs := testctx.uSampler.ReadNew()
	msg = NewMessage(params)
	testctx.ringQ.PolyToBigint(coeffs, params.N()/params.Slots(), msg.Value)

	for i := 0; i < params.Slots(); i++ {
		msg.Value[i].Mod(msg.Value[i], params.T())
	}

	return
}

func TestHPBFV(t *testing.T) {
	params := NewParametersFromLiteral(HPN13D10T128)
	testctx, err := genTestParams(params)
	if err != nil {
		panic(err)
	}

	// testParameters(testctx, t)
	testEncrypt(testctx, t)
	testEvaluator(testctx, t)
}

// func testParameters(testctx *testContext, t *testing.T) {

// 	params := testctx.params

// 	t.Run("Parameters/Generator", func(t *testing.T) {
// 		root := params.Root()
// 		root.Exp(root, big.NewInt(int64(params.Slots())), params.T())

// 		assert.Equal(t, root, params.B())
// 	})
// }

func testEncrypt(testctx *testContext, t *testing.T) {

	params := testctx.params
	slots := params.Slots()
	enc := testctx.encryptor
	dec := testctx.decryptor

	t.Run("Encode & Decode", func(t *testing.T) {
		msg := genTestVectors(testctx)

		pt := testctx.encoder.EncodeNew(msg)
		msgOut := testctx.decoder.DecodeNew(pt)

		for i := 0; i < slots; i++ {
			assert.Equal(t, msgOut.Value[i].Text(10), msg.Value[i].Text(10))
		}
	})

	t.Run("Encrypt & Decrypt", func(t *testing.T) {
		msg := genTestVectors(testctx)

		ct := enc.EncryptMsgNew(msg)
		msgOut := dec.DecryptToMsgNew(ct)

		for i := 0; i < slots; i++ {
			assert.Equal(t, msgOut.Value[i].Text(10), msg.Value[i].Text(10))
		}
	})

}

func testEvaluator(testctx *testContext, t *testing.T) {

	params := testctx.params
	slots := params.Slots()
	eval := testctx.eval
	enc := testctx.encryptor
	dec := testctx.decryptor

	t.Run(testString("Evaluator/Add/op1=Ciphertext/op2=Ciphertext", testctx.params), func(t *testing.T) {
		msg1 := genTestVectors(testctx)
		msg2 := genTestVectors(testctx)
		msg3 := NewMessage(params)

		for i := 0; i < params.Slots(); i++ {
			msg3.Value[i].Add(msg1.Value[i], msg2.Value[i])
			msg3.Value[i].Mod(msg3.Value[i], params.T())
		}

		ct1 := enc.EncryptMsgNew(msg1)
		ct2 := enc.EncryptMsgNew(msg2)
		ct3 := eval.AddNew(ct1, ct2)
		msgOut := dec.DecryptToMsgNew(ct3)

		for i := 0; i < slots; i++ {
			assert.Equal(t, msgOut.Value[i].Text(10), msg3.Value[i].Text(10))
		}

	})

	t.Run(testString("Evaluator/Sub/op1=Ciphertext/op2=Ciphertext", testctx.params), func(t *testing.T) {
		msg1 := genTestVectors(testctx)
		msg2 := genTestVectors(testctx)
		msg3 := NewMessage(params)

		for i := 0; i < params.Slots(); i++ {
			msg3.Value[i].Sub(msg1.Value[i], msg2.Value[i])
			msg3.Value[i].Mod(msg3.Value[i], params.T())
		}

		ct1 := enc.EncryptMsgNew(msg1)
		ct2 := enc.EncryptMsgNew(msg2)
		ct3 := eval.SubNew(ct1, ct2)
		msgOut := dec.DecryptToMsgNew(ct3)

		for i := 0; i < slots; i++ {
			assert.Equal(t, msgOut.Value[i].Text(10), msg3.Value[i].Text(10))
		}

	})

	t.Run(testString("Evaluator/Mul/op1=Ciphertext/op2=Ciphertext", testctx.params), func(t *testing.T) {
		msg1 := genTestVectors(testctx)
		msg2 := genTestVectors(testctx)
		msg3 := NewMessage(params)

		for i := 0; i < params.Slots(); i++ {
			msg3.Value[i].Mul(msg1.Value[i], msg2.Value[i])
			msg3.Value[i].Mod(msg3.Value[i], params.T())
		}

		ct1 := enc.EncryptMsgNew(msg1)
		ct2 := enc.EncryptMsgNew(msg2)
		ct3 := eval.MulAndRelinNew(ct1, ct2, testctx.rlk)
		msgOut := dec.DecryptToMsgNew(ct3)

		for i := 0; i < slots; i++ {
			assert.Equal(t, msgOut.Value[i].Text(10), msg3.Value[i].Text(10))
		}

	})

	t.Run(testString("Evaluator/Rotate", testctx.params), func(t *testing.T) {
		msg1 := genTestVectors(testctx)
		msg2 := NewMessage(params)

		for rotidx := 1; rotidx < slots; rotidx *= 2 {

			for i := 0; i < slots; i++ {
				if i-rotidx >= 0 {
					msg2.Value[i-rotidx].Set(msg1.Value[i])
				} else {
					msg2.Value[i-rotidx+slots].Set(msg1.Value[i])
				}
			}

			ct1 := enc.EncryptMsgNew(msg1)
			ct2 := eval.RotateColumnsNew(ct1, testctx.rtks, rotidx)
			msgOut := dec.DecryptToMsgNew(ct2)

			for i := 0; i < slots; i++ {
				assert.Equal(t, msgOut.Value[i].Text(10), msg2.Value[i].Text(10))
			}

		}

	})

	t.Run(testString("Evaluator/Neg", testctx.params), func(t *testing.T) {
		msg1 := genTestVectors(testctx)
		msg2 := NewMessage(params)

		for i := 0; i < slots; i++ {
			msg2.Value[i].Neg(msg1.Value[i])
			msg2.Value[i].Mod(msg2.Value[i], params.T())
		}

		ct1 := enc.EncryptMsgNew(msg1)
		ct2 := eval.NegNew(ct1)
		msgOut := dec.DecryptToMsgNew(ct2)

		for i := 0; i < slots; i++ {
			assert.Equal(t, msgOut.Value[i].Text(10), msg2.Value[i].Text(10))
		}

	})

}
