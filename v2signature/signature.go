package jarsigner

import (
	"bytes"
	"encoding/binary"
	"errors"
)

type APKSignatureV2Signature struct {
	AlgorithmID uint32
	Signature   []byte
}

func (signature *APKSignatureV2Signature) Parse(buf *bytes.Buffer) error {
	if buf.Len() < 8 {
		return errors.New("corrupted signature data sequence")
	}
	signature.AlgorithmID = binary.LittleEndian.Uint32(buf.Next(4))

	signatureBuffer, err := readLengthPrefixedSequence(buf)
	if err != nil {
		return err
	}
	signature.Signature = signatureBuffer.Bytes()
	return nil
}
