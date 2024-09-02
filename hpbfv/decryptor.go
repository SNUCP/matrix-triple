package hpbfv

import (
	"hp-bfv/rlwe"
)

type Decryptor struct {
	params   Parameters
	dec      rlwe.Decryptor
	dcd      *Decoder
	ptxtPool *Plaintext
}

func NewDecryptor(params Parameters, sk *rlwe.SecretKey) (dec *Decryptor) {
	dec = new(Decryptor)
	dec.params = params
	dec.dec = rlwe.NewDecryptor(params.Parameters, sk)
	dec.dcd = NewDecoder(params)
	dec.ptxtPool = NewPlaintext(params)

	return
}

func (dec *Decryptor) Decrypt(ctIn *Ciphertext, ptOut *Plaintext) {
	dec.dec.Decrypt(ctIn.Ciphertext, ptOut.Plaintext)
}

func (dec *Decryptor) DecryptToMsg(ctIn *Ciphertext, msgOut *Message) {
	dec.Decrypt(ctIn, dec.ptxtPool)
	dec.dcd.Decode(dec.ptxtPool, msgOut)
}

func (dec *Decryptor) DecryptNew(ctIn *Ciphertext) (ptOut *Plaintext) {
	ptOut = NewPlaintext(dec.params)
	dec.Decrypt(ctIn, ptOut)
	return
}

func (dec *Decryptor) DecryptToMsgNew(ctIn *Ciphertext) (msgOut *Message) {
	msgOut = NewMessage(dec.params)
	dec.DecryptToMsg(ctIn, msgOut)
	return
}
