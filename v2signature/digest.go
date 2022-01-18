package jarsigner

import (
	"bytes"
	"encoding/binary"
	"errors"
)

type APKSignatureV2Digest struct {
	SignatureAlgorithmID uint32
	Digest               []byte
}

func (digest *APKSignatureV2Digest) Parse(buf *bytes.Buffer) error {
	if buf.Len() < 8 {
		return errors.New("corrupted digest data sequence")
	}
	digest.SignatureAlgorithmID = binary.LittleEndian.Uint32(buf.Next(4))

	digestBuffer, err := readLengthPrefixedSequence(buf)
	if err != nil {
		return err
	}
	digest.Digest = digestBuffer.Bytes()
	return nil
}
