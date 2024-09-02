package hpbfv

import (
	"hp-bfv/rlwe"
)

type MatrixEncryptor struct {
	ecd *MatrixEncoder
	enc *Encryptor
	dec *Decryptor
}

// NewMatrixEncryptor creates a new MatrixEncryptor.
func NewMatrixEncryptor(params Parameters, pk *rlwe.PublicKey, sk *rlwe.SecretKey) (enc *MatrixEncryptor) {
	enc = new(MatrixEncryptor)
	enc.ecd = NewMatrixEncoder(params)
	enc.enc = NewEncryptor(params, pk)
	enc.dec = NewDecryptor(params, sk)
	return
}

// EncryptNew encrypts the input matrix and returns the ciphertext.
func (enc *MatrixEncryptor) EncryptNew(pm *MatrixPlaintext) (cm *MatrixCiphertext) {
	cm = NewMatrixCiphertext(enc.enc.params, len(pm.Value), pm.IsDiagonal)
	enc.Encrypt(pm, cm)
	return
}

// Encrypt encrypts the input matrix and returns the ciphertext.
func (enc *MatrixEncryptor) Encrypt(pm *MatrixPlaintext, cm *MatrixCiphertext) {
	cm.Pack = pm.Pack
	cm.IsDiagonal = pm.IsDiagonal

	for i := range pm.Value {
		enc.enc.Encrypt(pm.Value[i], cm.Value[i])
	}
}

// DecryptNew decrypts the input ciphertext and returns the plaintext.
func (enc *MatrixEncryptor) DecryptNew(cm *MatrixCiphertext) (pm *MatrixPlaintext) {
	pm = NewMatrixPlaintext(enc.dec.params, len(cm.Value), cm.IsDiagonal)
	enc.Decrypt(cm, pm)
	return
}

// Decrypt decrypts the input ciphertext and returns the plaintext.
func (enc *MatrixEncryptor) Decrypt(cm *MatrixCiphertext, pm *MatrixPlaintext) {
	pm.Pack = cm.Pack
	pm.IsDiagonal = cm.IsDiagonal

	for i := range cm.Value {
		enc.dec.Decrypt(cm.Value[i], pm.Value[i])
	}
}
