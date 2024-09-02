package hpbfv

import (
	"math/big"

	"hp-bfv/ring"
	"hp-bfv/rlwe"
)

type ParametersLiteral struct {
	LogN    int // Log Ring degree (power of 2)
	Q       []uint64
	QMul    []uint64
	P       []uint64
	LogQ    []int   `json:",omitempty"`
	LogQMul []int   `json:",omitempty"`
	LogP    []int   `json:",omitempty"`
	H       int     // hamming weight of key
	Sigma   float64 // Gaussian sampling standard deviation
	//plaintext parameters: X^D - B
	B *big.Int // plaintext basis
	D uint64   // plaintext degree
	G *big.Int // generators of Z_t s.t g^((p-1)/2k) = B
}

type Parameters struct {
	rlwe.Parameters
	ringQMul *ring.Ring
	b        *big.Int
	d        uint64
	g        *big.Int
	t        *big.Int //plaint text modulus
}

func NewParametersFromLiteral(pl ParametersLiteral) (params Parameters) {
	rlweParams, err := rlwe.NewParametersFromLiteral(rlwe.ParametersLiteral{LogN: pl.LogN, Q: pl.Q, P: pl.P, LogQ: pl.LogQ, LogP: pl.LogP, H: pl.H, Sigma: pl.Sigma})
	if err != nil {
		panic("cannot NewParametersFromLiteral: rlweParams cannot be generated")
	}

	N := (1 << pl.LogN)
	K := N / int(pl.D)

	ringQMul, err := ring.NewRing(N, pl.QMul)
	if err != nil {
		panic("cannot NewParametersFromLiteral: ring QMul cannot be generated")
	}

	params.Parameters = rlweParams
	params.ringQMul = ringQMul
	params.b = new(big.Int).Set(pl.B)
	params.d = pl.D
	params.g = new(big.Int).Set(pl.G)
	params.t = new(big.Int).Exp(pl.B, big.NewInt(int64(K)), nil)
	params.t.Add(params.t, big.NewInt(1))

	if !params.t.ProbablyPrime(0) {
		panic("cannot NewParametersFromLiteral: T is not a prime")
	}

	BK := new(big.Int).Exp(pl.B, big.NewInt(int64(K)), nil)
	if BK.Mod(BK, big.NewInt(int64(2*N))).Int64() != 0 {
		panic("cannot NewParametersFromLiteral: 2N does not divide b^k")
	}

	return
}

func (p Parameters) RingQMul() *ring.Ring {
	return p.ringQMul
}

func (p Parameters) GaloisElementForColumnRotationBy(rotidx uint64) uint64 {
	k := p.N() / p.Slots()
	ret := ring.ModExp(5, rotidx*uint64(k/2), uint64(2*p.N()))

	return ret
}

func (p Parameters) Slots() int {
	return int(p.d)
}

func (p Parameters) Root() *big.Int {
	e := new(big.Int).Sub(p.t, big.NewInt(1))
	e.Div(e, big.NewInt(2*int64(p.N())))
	return new(big.Int).Exp(p.g, e, p.t)
}

func (p Parameters) B() *big.Int {
	return new(big.Int).Set(p.b)
}

func (p Parameters) D() uint64 {
	return p.d
}

func (p Parameters) G() *big.Int {
	return new(big.Int).Set(p.g)
}

func (p Parameters) T() *big.Int {
	return new(big.Int).Set(p.t)
}
