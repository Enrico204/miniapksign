package jarsigner

import (
	"bytes"
	"encoding/binary"
	"errors"
)

type APKSignatureV2AdditionalAttribute struct {
	ID    uint32
	Value []byte
}

func (digest *APKSignatureV2AdditionalAttribute) Parse(buf *bytes.Buffer) error {
	if buf.Len() < 8 {
		return errors.New("corrupted additional attribute data sequence")
	}
	digest.ID = binary.LittleEndian.Uint32(buf.Next(4))

	valueBuffer, err := readLengthPrefixedSequence(buf)
	if err != nil {
		return err
	}
	digest.Value = valueBuffer.Bytes()
	return nil
}
