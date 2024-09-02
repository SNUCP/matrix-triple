package hpbfv

import (
	"math/big"

	"hp-bfv/ring"
)

type Encoder struct {
	params Parameters

	polyPool *ring.Poly

	nttRoots   *Message
	rootPows   *Message
	msgPool    *Message
	coeffPool1 []*big.Int
	coeffPool2 []*big.Int

	dInvModT *big.Int

	indexMap []int
}

func NewEncoder(params Parameters) (ecd *Encoder) {
	ecd = new(Encoder)
	ecd.params = params
	ecd.polyPool = params.RingQ().NewPoly()
	ecd.nttRoots = NewMessage(params)
	ecd.rootPows = NewMessage(params)
	ecd.msgPool = NewMessage(params)
	ecd.indexMap = make([]int, params.Slots())
	ecd.dInvModT = new(big.Int).ModInverse(big.NewInt(int64(params.Slots())), params.T())
	ecd.coeffPool1 = make([]*big.Int, params.N())
	ecd.coeffPool2 = make([]*big.Int, params.N())
	for i := 0; i < params.N(); i++ {
		ecd.coeffPool1[i] = big.NewInt(0)
		ecd.coeffPool2[i] = big.NewInt(0)
	}

	slots := params.Slots()
	root := params.Root()
	roots := ecd.nttRoots
	rootPows := ecd.rootPows
	k := params.N() / params.Slots()

	//compute i-th root and minus i-th power of root
	for i := 0; i < slots; i++ {
		roots.Value[i].Exp(root, big.NewInt(int64(2*params.N()-2*k*i)), params.T())
		rootPows.Value[i].Exp(root, big.NewInt(int64(2*params.N()-i)), params.T())
	}

	//compute indexMap[5^(ik/2)/2k)] = i
	for i := 0; i < slots; i++ {
		idx := ring.ModExp(5, uint64(i*k/2), uint64(params.N()*2)) / uint64(2*k)
		ecd.indexMap[idx] = i
	}

	return
}

func (ecd *Encoder) invNtt(msgIn, msgOut *Message) {

	ecd.permute(msgIn, ecd.msgPool)

	slots := ecd.params.Slots()
	roots := ecd.nttRoots

	for i := 0; i < slots; i++ {
		msgOut.Value[i].Set(ecd.msgPool.Value[i])
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
				v := new(big.Int).Exp(roots.Value[k], big.NewInt(int64(step)), ecd.params.T())
				v.Mul(msgOut.Value[j+k+i/2], v)
				msgOut.Value[j+k].Add(u, v)
				msgOut.Value[j+k+i/2].Sub(u, v)

				msgOut.Value[j+k].Mod(msgOut.Value[j+k], ecd.params.T())
				msgOut.Value[j+k+i/2].Mod(msgOut.Value[j+k+i/2], ecd.params.T())
			}
		}
	}

	for i := 0; i < slots; i++ {
		msgOut.Value[i].Mul(msgOut.Value[i], ecd.rootPows.Value[i])
		msgOut.Value[i].Mul(msgOut.Value[i], ecd.dInvModT)
		msgOut.Value[i].Mod(msgOut.Value[i], ecd.params.T())
	}

}

func (ecd *Encoder) permute(msgIn, msgOut *Message) {
	if msgIn == msgOut {
		panic("Cannot permute: input and output message should be different!!")
	}

	slots := ecd.params.Slots()

	for i := 0; i < slots; i++ {
		msgOut.Value[i].Set(msgIn.Value[ecd.indexMap[i]])
	}
}

func (ecd *Encoder) EncodeNew(msgIn *Message) (ptxtOut *Plaintext) {
	ptxtOut = NewPlaintext(ecd.params)
	ecd.Encode(msgIn, ptxtOut)
	return
}

func (ecd *Encoder) Encode(msgIn *Message, ptxtOut *Plaintext) {
	params := ecd.params

	ecd.invNtt(msgIn, ecd.msgPool)

	// mult (X^(N-D) + bX^(N-2D) + ...)
	d := params.Slots()
	k := params.N() / d

	for i := 0; i < k; i++ {
		ecd.coeffPool1[i*d].Exp(params.b, big.NewInt(int64(k-i-1)), nil)
	}

	for i := 0; i < params.N(); i++ {
		ecd.coeffPool2[i].SetInt64(0)
	}

	for i := 0; i < k; i++ {
		for j := 0; j < d; j++ {
			e := j + i*d
			tmp := new(big.Int).Mul(ecd.msgPool.Value[j], ecd.coeffPool1[i*d])
			ecd.coeffPool2[e].Sub(ecd.coeffPool2[e], tmp)
		}
	}

	// scale by Q/T

	tHalf := new(big.Int).Div(params.T(), big.NewInt(2))
	for i := 0; i < params.N(); i++ {
		ecd.coeffPool2[i].Mul(ecd.coeffPool2[i], params.QBigInt())
		ecd.coeffPool2[i].Add(ecd.coeffPool2[i], tHalf)
		ecd.coeffPool2[i].Div(ecd.coeffPool2[i], params.T())
	}

	params.RingQ().SetCoefficientsBigint(ecd.coeffPool2, ptxtOut.Value)
}
