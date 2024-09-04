package hpbfv

import (
	"math"

	"hp-bfv/ring"
	"hp-bfv/rlwe"
	"hp-bfv/rlwe/ringqp"
	"hp-bfv/utils"
)

type MatrixEvaluator struct {
	eval *Evaluator

	poolAMul [][2]*ringqp.Poly
	poolBMul [][2]*ringqp.Poly

	poolRot  [2]*ringqp.Poly
	poolCMul [4]*ringqp.Poly
	poolC    [4]*ring.Poly

	poolKeySwitch [3]*rlwe.Ciphertext

	permuteQIdx    map[uint64][]uint64
	permuteQMulIdx map[uint64][]uint64

	rlk *rlwe.RelinearizationKey
	rks *rlwe.RotationKeySet
}

func NewQQMulPoly(params Parameters) *ringqp.Poly {
	return &ringqp.Poly{Q: params.RingQ().NewPoly(), P: params.RingQMul().NewPoly()}
}

// NewMatrixEvaluator creates a new MatrixEvaluator.
func NewMatrixEvaluator(params Parameters, rlk *rlwe.RelinearizationKey, matRks *rlwe.RotationKeySet) *MatrixEvaluator {
	eval := new(MatrixEvaluator)

	eval.eval = NewEvaluator(params)

	dim := params.Slots()
	eval.poolAMul = make([][2]*ringqp.Poly, dim)
	eval.poolBMul = make([][2]*ringqp.Poly, dim)
	for i := 0; i < dim; i++ {
		eval.poolAMul[i] = [2]*ringqp.Poly{NewQQMulPoly(params), NewQQMulPoly(params)}
		eval.poolBMul[i] = [2]*ringqp.Poly{NewQQMulPoly(params), NewQQMulPoly(params)}
	}

	eval.poolRot = [2]*ringqp.Poly{NewQQMulPoly(params), NewQQMulPoly(params)}

	eval.poolCMul = [4]*ringqp.Poly{
		NewQQMulPoly(params), NewQQMulPoly(params),
		NewQQMulPoly(params), NewQQMulPoly(params),
	}
	eval.poolC = [4]*ring.Poly{
		params.RingQ().NewPoly(), params.RingQ().NewPoly(),
		params.RingQ().NewPoly(), params.RingQ().NewPoly(),
	}

	eval.poolKeySwitch = [3]*rlwe.Ciphertext{
		rlwe.NewCiphertext(params.Parameters, 1, params.MaxLevel()),
		rlwe.NewCiphertext(params.Parameters, 1, params.MaxLevel()),
		rlwe.NewCiphertext(params.Parameters, 1, params.MaxLevel()),
	}

	eval.permuteQIdx = make(map[uint64][]uint64, dim)
	eval.permuteQMulIdx = make(map[uint64][]uint64, dim)
	for i := 0; i < dim; i++ {
		galEl := params.GaloisElementForColumnRotationBy(uint64(i))
		eval.permuteQIdx[galEl] = params.RingQ().PermuteNTTIndex(galEl)
		eval.permuteQMulIdx[galEl] = params.RingQMul().PermuteNTTIndex(galEl)
	}

	eval.rlk = rlk
	eval.rks = matRks

	return eval
}

// MulNew multiplies two matrices.
func (eval *MatrixEvaluator) MulNew(ctA, ctB *MatrixCiphertext) *MatrixCiphertext {
	ctC := NewMatrixCiphertext(eval.eval.params, len(ctA.Value), true)
	eval.Mul(ctA, ctB, ctC)
	return ctC
}

// Mul multiplies two matrices.
func (eval *MatrixEvaluator) Mul(ctA, ctB, ctC *MatrixCiphertext) {
	if !(ctA.IsDiagonal && !ctB.IsDiagonal && ctC.IsDiagonal) {
		panic("wrong encoding")
	}

	pack := ctA.Pack
	dim := len(ctA.Value)
	if len(ctB.Value) != dim || len(ctC.Value) != dim {
		panic("wrong encoding")
	}
	if ctB.Pack != pack || ctC.Pack != pack {
		panic("wrong encoding")
	}
	if pack*dim != eval.eval.params.Slots() {
		panic("wrong encoding")
	}

	params := eval.eval.params
	ringQ := params.RingQ()
	ringQMul := params.RingQMul()
	levelQ := len(ringQ.Modulus) - 1
	levelQMul := len(ringQMul.Modulus) - 1

	// Fill poolAMul
	for i := 0; i < dim; i++ {
		for j := 0; j < 2; j++ {
			ringQ.MulScalarBigint(ctA.Value[i].Value[j], ringQMul.ModulusAtLevel[len(ringQMul.Modulus)-1], eval.poolAMul[i][j].Q)
			eval.poolAMul[i][j].P.Zero()

			eval.eval.conv.ModDownQPtoP(levelQ, levelQMul, eval.poolAMul[i][j].Q, eval.poolAMul[i][j].P, eval.poolAMul[i][j].P)
			eval.eval.conv.ModUpPtoQ(levelQMul, levelQ, eval.poolAMul[i][j].P, eval.poolAMul[i][j].Q)

			ringQ.NTT(eval.poolAMul[i][j].Q, eval.poolAMul[i][j].Q)
			ringQMul.NTT(eval.poolAMul[i][j].P, eval.poolAMul[i][j].P)

			ringQ.MForm(eval.poolAMul[i][j].Q, eval.poolAMul[i][j].Q)
			ringQMul.MForm(eval.poolAMul[i][j].P, eval.poolAMul[i][j].P)
		}
	}

	// Fill poolBMul
	for i := 0; i < dim; i++ {
		for j := 0; j < 2; j++ {
			eval.poolBMul[i][j].Q.Copy(ctB.Value[i].Value[j])
			eval.eval.conv.ModUpQtoP(levelQ, levelQMul, eval.poolBMul[i][j].Q, eval.poolBMul[i][j].P)

			ringQ.NTT(eval.poolBMul[i][j].Q, eval.poolBMul[i][j].Q)
			ringQMul.NTT(eval.poolBMul[i][j].P, eval.poolBMul[i][j].P)
		}
	}

	QMargin := int(math.Exp2(64)/float64(utils.MaxSliceUint64(ringQ.Modulus))) >> 1
	QMulMargin := int(math.Exp2(64)/float64(utils.MaxSliceUint64(ringQMul.Modulus))) >> 1

	// Compute the multiplication
	for i := 0; i < dim; i++ {
		galEl := eval.eval.params.GaloisElementForColumnRotationBy(uint64(pack * i))

		for j := 0; j < 4; j++ {
			eval.poolCMul[j].Q.Zero()
			eval.poolCMul[j].P.Zero()
			eval.poolC[j].Zero()
		}

		var reduce int
		for j := 0; j < dim; j++ {
			bIdx := (dim + i - j) % dim
			ringQ.PermuteNTTWithIndexLvl(levelQ, eval.poolBMul[bIdx][0].Q, eval.permuteQIdx[galEl], eval.poolRot[0].Q)
			ringQ.PermuteNTTWithIndexLvl(levelQ, eval.poolBMul[bIdx][1].Q, eval.permuteQIdx[galEl], eval.poolRot[1].Q)
			ringQMul.PermuteNTTWithIndexLvl(levelQMul, eval.poolBMul[bIdx][0].P, eval.permuteQMulIdx[galEl], eval.poolRot[0].P)
			ringQMul.PermuteNTTWithIndexLvl(levelQMul, eval.poolBMul[bIdx][1].P, eval.permuteQMulIdx[galEl], eval.poolRot[1].P)

			ringQ.MulCoeffsMontgomeryConstantAndAddNoMod(eval.poolAMul[j][0].Q, eval.poolRot[0].Q, eval.poolCMul[0].Q)
			ringQMul.MulCoeffsMontgomeryConstantAndAddNoMod(eval.poolAMul[j][0].P, eval.poolRot[0].P, eval.poolCMul[0].P) // 1

			ringQ.MulCoeffsMontgomeryConstantAndAddNoMod(eval.poolAMul[j][1].Q, eval.poolRot[0].Q, eval.poolCMul[1].Q)
			ringQMul.MulCoeffsMontgomeryConstantAndAddNoMod(eval.poolAMul[j][1].P, eval.poolRot[0].P, eval.poolCMul[1].P) // s

			ringQ.MulCoeffsMontgomeryConstantAndAddNoMod(eval.poolAMul[j][0].Q, eval.poolRot[1].Q, eval.poolCMul[2].Q)
			ringQMul.MulCoeffsMontgomeryConstantAndAddNoMod(eval.poolAMul[j][0].P, eval.poolRot[1].P, eval.poolCMul[2].P) // rot(s)

			ringQ.MulCoeffsMontgomeryConstantAndAddNoMod(eval.poolAMul[j][1].Q, eval.poolRot[1].Q, eval.poolCMul[3].Q)
			ringQMul.MulCoeffsMontgomeryConstantAndAddNoMod(eval.poolAMul[j][1].P, eval.poolRot[1].P, eval.poolCMul[3].P) // s*rot(s)

			if reduce%QMargin == QMargin-1 {
				ringQ.Reduce(eval.poolCMul[0].Q, eval.poolCMul[0].Q)
				ringQ.Reduce(eval.poolCMul[1].Q, eval.poolCMul[1].Q)
				ringQ.Reduce(eval.poolCMul[2].Q, eval.poolCMul[2].Q)
				ringQ.Reduce(eval.poolCMul[3].Q, eval.poolCMul[3].Q)
			}
			if reduce%QMulMargin == QMulMargin-1 {
				ringQMul.Reduce(eval.poolCMul[0].P, eval.poolCMul[0].P)
				ringQMul.Reduce(eval.poolCMul[1].P, eval.poolCMul[1].P)
				ringQMul.Reduce(eval.poolCMul[2].P, eval.poolCMul[2].P)
				ringQMul.Reduce(eval.poolCMul[3].P, eval.poolCMul[3].P)
			}
			reduce++
		}

		if reduce%QMargin != 0 {
			ringQ.Reduce(eval.poolCMul[0].Q, eval.poolCMul[0].Q)
			ringQ.Reduce(eval.poolCMul[1].Q, eval.poolCMul[1].Q)
			ringQ.Reduce(eval.poolCMul[2].Q, eval.poolCMul[2].Q)
			ringQ.Reduce(eval.poolCMul[3].Q, eval.poolCMul[3].Q)
		}
		if reduce%QMulMargin != 0 {
			ringQMul.Reduce(eval.poolCMul[0].P, eval.poolCMul[0].P)
			ringQMul.Reduce(eval.poolCMul[1].P, eval.poolCMul[1].P)
			ringQMul.Reduce(eval.poolCMul[2].P, eval.poolCMul[2].P)
			ringQMul.Reduce(eval.poolCMul[3].P, eval.poolCMul[3].P)
		}

		for j := 0; j < 4; j++ {
			ringQ.InvNTT(eval.poolCMul[j].Q, eval.poolCMul[j].Q)
			ringQMul.InvNTT(eval.poolCMul[j].P, eval.poolCMul[j].P)

			eval.eval.conv.ModDownQPtoQ(levelQ, levelQMul, eval.poolCMul[j].Q, eval.poolCMul[j].P, eval.poolCMul[j].Q)

			ringQ.MultByMonomial(eval.poolCMul[j].Q, params.Slots(), eval.poolC[j])
			ringQ.MulScalarBigint(eval.poolCMul[j].Q, params.b, eval.poolCMul[j].Q)
			ringQ.Sub(eval.poolC[j], eval.poolCMul[j].Q, eval.poolC[j])
		}

		ctC.Value[i].Value[0].Copy(eval.poolC[0])
		ctC.Value[i].Value[1].Copy(eval.poolC[1])

		// KeySwitch rot(s) -> (1, s)
		eval.eval.ksw.GadgetProductNoPNoModDown(levelQ, eval.poolC[2], eval.rks.Keys[galEl].GadgetCiphertext, eval.poolKeySwitch[0])

		// KeySwitch s*rot(s) -> (s, s^2)
		eval.eval.ksw.GadgetProductNoPNoModDown(levelQ, eval.poolC[3], eval.rks.Keys[galEl].GadgetCiphertext, eval.poolKeySwitch[1])
		ringQ.Add(eval.poolKeySwitch[1].Value[0], eval.poolKeySwitch[0].Value[1], eval.poolKeySwitch[0].Value[1])

		// KeySwitch s^2 -> (1, s)
		ringQ.InvNTT(eval.poolKeySwitch[1].Value[1], eval.poolKeySwitch[1].Value[1])
		eval.eval.ksw.GadgetProductNoPNoModDown(levelQ, eval.poolKeySwitch[1].Value[1], eval.rlk.Keys[0].GadgetCiphertext, eval.poolKeySwitch[2])
		ringQ.Add(eval.poolKeySwitch[2].Value[0], eval.poolKeySwitch[0].Value[0], eval.poolKeySwitch[0].Value[0])
		ringQ.Add(eval.poolKeySwitch[2].Value[1], eval.poolKeySwitch[0].Value[1], eval.poolKeySwitch[0].Value[1])

		ringQ.InvNTT(eval.poolKeySwitch[0].Value[0], eval.poolKeySwitch[0].Value[0])
		ringQ.InvNTT(eval.poolKeySwitch[0].Value[1], eval.poolKeySwitch[0].Value[1])

		ringQ.Add(ctC.Value[i].Value[0], eval.poolKeySwitch[0].Value[0], ctC.Value[i].Value[0])
		ringQ.Add(ctC.Value[i].Value[1], eval.poolKeySwitch[0].Value[1], ctC.Value[i].Value[1])
	}
}
