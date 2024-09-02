package hpbfv

import (
	"hp-bfv/rlwe"
)

type Encryptor struct {
	params   Parameters
	enc      rlwe.Encryptor
	ecd      *Encoder
	ptxtPool *Plaintext
}

func NewEncryptor(params Parameters, pk *rlwe.PublicKey) (enc *Encryptor) {
	enc = new(Encryptor)
	enc.params = params
	enc.ptxtPool = NewPlaintext(params)
	enc.enc = rlwe.NewEncryptor(params.Parameters, pk)
	enc.ecd = NewEncoder(params)
	return
}

func (enc *Encryptor) Encrypt(ptxtIn *Plaintext, ctxtOut *Ciphertext) {
	enc.enc.Encrypt(ptxtIn.Plaintext, ctxtOut.Ciphertext)
}

func (enc *Encryptor) EncryptMsg(msgIn *Message, ctxtOut *Ciphertext) {
	enc.ecd.Encode(msgIn, enc.ptxtPool)
	enc.enc.Encrypt(enc.ptxtPool.Plaintext, ctxtOut.Ciphertext)
}

func (enc *Encryptor) EncryptNew(ptxtIn *Plaintext) (ctxtOut *Ciphertext) {
	ctxtOut = NewCiphertext(enc.params, 1)
	enc.Encrypt(ptxtIn, ctxtOut)
	return
}

func (enc *Encryptor) EncryptMsgNew(msgIn *Message) (ctxtOut *Ciphertext) {
	ctxtOut = NewCiphertext(enc.params, 1)
	enc.EncryptMsg(msgIn, ctxtOut)
	return
}
