package hpbfv

import (
	"math/big"

	"hp-bfv/ring"
)

type Decoder struct {
	params Parameters

	polyPool *ring.Poly

	nttRoots   *Message
	msgPool    *Message
	coeffPool1 []*big.Int
	coeffPool2 []*big.Int
}

func NewDecoder(params Parameters) (dcd *Decoder) {
	dcd = new(Decoder)
	dcd.params = params
	dcd.polyPool = params.RingQ().NewPoly()
	dcd.nttRoots = NewMessage(params)
	dcd.msgPool = NewMessage(params)
	dcd.coeffPool1 = make([]*big.Int, params.N())
	dcd.coeffPool2 = make([]*big.Int, params.N())
	for i := 0; i < params.N(); i++ {
		dcd.coeffPool1[i] = big.NewInt(0)
		dcd.coeffPool2[i] = big.NewInt(0)
	}

	slots := params.Slots()
	root := params.Root()
	roots := dcd.nttRoots
	k := params.N() / params.Slots()

	//compute ntt roots
	for i := 0; i < slots; i++ {
		//roots.Value[i].Exp(root, big.NewInt(int64(2*k*i+1)), params.T)
		e := ring.ModExp(5, uint64((k/2)*i), uint64(params.N()*2))
		roots.Value[i].Exp(root, big.NewInt(int64(e)), params.T())
	}

	return
}

func (dcd *Decoder) ntt(msgIn, msgOut *Message) {
	slots := dcd.params.Slots()
	roots := dcd.nttRoots

	if msgIn != msgOut {
		for i := 0; i < slots; i++ {
			msgOut.Value[i].Set(msgIn.Value[i])
		}
	}

	//apply bit reversal
	j := 0
	for i := 1; i < slots; i++ {
		bit := (slots >> 1)
		for j >= bit {
			j -= bit
			bit >>= 1
		}
		j += bit
		if i < j {
			msgOut.Value[i], msgOut.Value[j] = msgOut.Value[j], msgOut.Value[i]
		}
	}

	//apply inplace NTT
	for i := 2; i <= slots; i <<= 1 {
		step := slots / i
		for j := 0; j < slots; j += i {
			for k := 0; k < i/2; k++ {
				u := new(big.Int).Set(msgOut.Value[j+k])
				v := new(big.Int).Exp(roots.Value[k], big.NewInt(int64(step)), dcd.params.T())
				v.Mul(msgOut.Value[j+k+i/2], v)
				msgOut.Value[j+k].Add(u, v)
				msgOut.Value[j+k+i/2].Sub(u, v)

				msgOut.Value[j+k].Mod(msgOut.Value[j+k], dcd.params.T())
				msgOut.Value[j+k+i/2].Mod(msgOut.Value[j+k+i/2], dcd.params.T())
			}
		}
	}

	for i := 0; i < slots; i++ {
		msgOut.Value[i].Mod(msgOut.Value[i], dcd.params.T())
	}
}

func (dcd *Decoder) DecodeNew(ptxtIn *Plaintext) (msgOut *Message) {
	msgOut = NewMessage(dcd.params)
	dcd.Decode(ptxtIn, msgOut)
	return
}

func (dcd *Decoder) Decode(ptxtIn *Plaintext, msgOut *Message) {
	params := dcd.params
	ringQ := params.RingQ()
	slots := params.Slots()
	d := int(params.D())

	for i := 0; i < params.N(); i++ {
		dcd.coeffPool1[i].SetInt64(0)
		dcd.coeffPool2[i].SetInt64(0)
	}

	// mult (X^d-b)/q to ptxt

	ringQ.PolyToBigint(ptxtIn.Value, 1, dcd.coeffPool1)

	for i := 0; i < params.N(); i++ {
		tmp := new(big.Int).Mul(dcd.coeffPool1[i], new(big.Int).Neg(params.b))
		dcd.coeffPool2[i].Add(dcd.coeffPool2[i], tmp)

		if i+d < params.N() {
			dcd.coeffPool2[i+d].Add(dcd.coeffPool2[i+d], dcd.coeffPool1[i])
		} else {
			dcd.coeffPool2[i+d-params.N()].Sub(dcd.coeffPool2[i+d-params.N()], dcd.coeffPool1[i])
		}
	}

	qHalf := new(big.Int).Div(params.QBigInt(), big.NewInt(2))
	for i := 0; i < params.N(); i++ {
		dcd.coeffPool2[i].Add(dcd.coeffPool2[i], qHalf)
		dcd.coeffPool2[i].Div(dcd.coeffPool2[i], params.QBigInt())
	}

	for i := params.N() - 1; i >= slots; i-- {
		dcd.coeffPool2[i].Mul(dcd.coeffPool2[i], params.b)
		dcd.coeffPool2[i-slots].Add(dcd.coeffPool2[i-slots], dcd.coeffPool2[i])
		dcd.coeffPool2[i-slots].Mod(dcd.coeffPool2[i-slots], dcd.params.T())
	}

	//apply NTT

	for i := 0; i < slots; i++ {
		dcd.msgPool.Value[i].Set(dcd.coeffPool2[i])
	}

	dcd.ntt(dcd.msgPool, msgOut)
}
