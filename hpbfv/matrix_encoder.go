package hpbfv

import (
	"math/big"
)

type MatrixEncoder struct {
	ecd *Encoder
	dcd *Decoder
}

// NewMatrixEncoder creates a new MatrixEncoder.
func NewMatrixEncoder(params Parameters) (ecd *MatrixEncoder) {
	ecd = new(MatrixEncoder)
	ecd.ecd = NewEncoder(params)
	ecd.dcd = NewDecoder(params)
	return
}

// EncodeMatrixMessageNew encodes a Matrix into a MatrixMessage.
func (ecd *MatrixEncoder) EncodeMatrixMessageNew(matrices [][][]*big.Int, isDiagonal bool) (em *MatrixMessage) {
	em = NewMatrixMessage(ecd.ecd.params, len(matrices[0]), isDiagonal)
	ecd.EncodeMatrixMessage(matrices, isDiagonal, em)
	return em
}

// EncodeMatrixMessage encodes a Matrix into a MatrixMessage.
func (ecd *MatrixEncoder) EncodeMatrixMessage(matrices [][][]*big.Int, isDiagonal bool, em *MatrixMessage) {
	pack := len(matrices)
	dim := len(matrices[0])
	if pack*dim != ecd.ecd.params.Slots() {
		panic("pack * dim must be equal to the number of slots")
	}

	em.Pack = pack
	em.IsDiagonal = isDiagonal

	if isDiagonal {
		for l := 0; l < pack; l++ {
			for i := 0; i < dim; i++ {
				for j := 0; j < dim; j++ {
					em.Value[i].Value[j*pack+l] = matrices[l][j][(j+i)%dim]
				}
			}
		}
	} else {
		for l := 0; l < pack; l++ {
			for i := 0; i < dim; i++ {
				for j := 0; j < dim; j++ {
					em.Value[i].Value[j*pack+l] = matrices[l][(dim+j-i)%dim][j]
				}
			}
		}
	}
}

// EncodeMatrixNew encodes a Matrix into a Plaintext.
func (ecd *MatrixEncoder) EncodeMatrixNew(matrices [][][]*big.Int, isDiagonal bool) (pt *MatrixPlaintext) {
	pt = NewMatrixPlaintext(ecd.ecd.params, len(matrices[0]), isDiagonal)
	ecd.EncodeMatrix(matrices, isDiagonal, pt)
	return pt
}

// EncodeMatrix encodes a Matrix into a Plaintext.
func (ecd *MatrixEncoder) EncodeMatrix(matrices [][][]*big.Int, isDiagonal bool, pt *MatrixPlaintext) {
	em := ecd.EncodeMatrixMessageNew(matrices, isDiagonal)

	pt.Pack = em.Pack
	pt.IsDiagonal = em.IsDiagonal
	for i := range em.Value {
		ecd.ecd.Encode(em.Value[i], pt.Value[i])
	}
}

// DecodeMatrixMessageNew decodes a MatrixMessage into a Matrix.
func (ecd *MatrixEncoder) DecodeMatrixMessageNew(em *MatrixMessage) (matrices [][][]*big.Int) {
	pack := em.Pack
	dim := len(em.Value)

	matrices = make([][][]*big.Int, pack)
	for l := 0; l < em.Pack; l++ {
		matrices[l] = make([][]*big.Int, dim)
		for i := range em.Value {
			matrices[l][i] = make([]*big.Int, dim)
			for j := range em.Value {
				matrices[l][i][j] = big.NewInt(0)
			}
		}
	}

	ecd.DecodeMatrixMessage(em, matrices)

	return
}

// DecodeMatrixMessage decodes a MatrixMessage into a Matrix.
func (ecd *MatrixEncoder) DecodeMatrixMessage(em *MatrixMessage, matrices [][][]*big.Int) {
	pack := em.Pack
	dim := len(em.Value)

	if em.IsDiagonal {
		for l := 0; l < pack; l++ {
			for i := 0; i < dim; i++ {
				for j := 0; j < dim; j++ {
					matrices[l][j][(j+i)%dim] = em.Value[i].Value[j*pack+l]
				}
			}
		}
	} else {
		for l := 0; l < pack; l++ {
			for i := 0; i < dim; i++ {
				for j := 0; j < dim; j++ {
					matrices[l][(dim+j-i)%dim][j] = em.Value[i].Value[j*pack+l]
				}
			}
		}
	}
}

// DecodeMatrixNew decodes a Plaintext into a Matrix.
func (ecd *MatrixEncoder) DecodeMatrixNew(pt *MatrixPlaintext) (matrices [][][]*big.Int) {
	em := NewMatrixMessage(ecd.ecd.params, len(pt.Value), pt.IsDiagonal)
	for i := range pt.Value {
		ecd.dcd.Decode(pt.Value[i], em.Value[i])
	}

	matrices = ecd.DecodeMatrixMessageNew(em)
	return
}

// DecodeMatrix decodes a Plaintext into a Matrix.
func (ecd *MatrixEncoder) DecodeMatrix(pt *MatrixPlaintext, matrices [][][]*big.Int) {
	em := NewMatrixMessage(ecd.ecd.params, len(pt.Value), pt.IsDiagonal)
	for i := range pt.Value {
		ecd.dcd.Decode(pt.Value[i], em.Value[i])
	}

	ecd.DecodeMatrixMessage(em, matrices)
}
