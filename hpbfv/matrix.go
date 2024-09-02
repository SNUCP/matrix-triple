package hpbfv

type MatrixMessage struct {
	// MatrixMessage may pack several matrices into one.
	Value []*Message

	// Pack is the number of matrices packed into one.
	Pack int
	// If true, matrices are packed diagonally.
	// If false, matrices are packed shifted diagonally.
	IsDiagonal bool
}

// NewMatrixMessage creates a new MatrixMessage.
func NewMatrixMessage(params Parameters, dim int, isDiagonal bool) (em *MatrixMessage) {
	if params.Slots()%dim != 0 {
		panic("dim must divide d")
	}

	pack := params.Slots() / dim

	em = new(MatrixMessage)
	em.Pack = pack
	em.IsDiagonal = isDiagonal
	em.Value = make([]*Message, dim)
	for i := range em.Value {
		em.Value[i] = NewMessage(params)
	}

	return
}

type MatrixPlaintext struct {
	Value []*Plaintext

	Pack       int
	IsDiagonal bool
}

// NewMatrixPlaintext creates a new PlainMatrix.
func NewMatrixPlaintext(params Parameters, dim int, isDiagonal bool) (pm *MatrixPlaintext) {
	if params.Slots()%dim != 0 {
		panic("dim must divide d")
	}

	pack := params.Slots() / dim

	pm = new(MatrixPlaintext)
	pm.Pack = pack
	pm.IsDiagonal = isDiagonal
	pm.Value = make([]*Plaintext, dim)
	for i := range pm.Value {
		pm.Value[i] = NewPlaintext(params)
	}

	return
}

type MatrixCiphertext struct {
	Value []*Ciphertext

	Pack       int
	IsDiagonal bool
}

// NewMatrixCiphertext creates a new EncryptedMatrix.
func NewMatrixCiphertext(params Parameters, dim int, isDiagonal bool) (cm *MatrixCiphertext) {
	if int(params.Slots())%dim != 0 {
		panic("dim must divide d")
	}

	pack := params.Slots() / dim

	cm = new(MatrixCiphertext)
	cm.Pack = pack
	cm.IsDiagonal = isDiagonal
	cm.Value = make([]*Ciphertext, dim)
	for i := range cm.Value {
		cm.Value[i] = NewCiphertext(params, 1)
	}

	return
}
