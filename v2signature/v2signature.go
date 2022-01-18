package jarsigner

import (
	"bytes"
	"encoding/binary"
	"errors"
)

// See https://source.android.com/security/apksigning/v2.html#verification

type APKSignatureV2 struct {
	Signers []APKSignatureV2Signer
}

func (sig *APKSignatureV2) Parse(buf *bytes.Buffer) error {
	signersBuffer, err := readLengthPrefixedSequence(buf)
	if err != nil {
		return err
	}

	// For each signer
	for signersBuffer.Len() > 0 {
		signerBuffer, err := readLengthPrefixedSequence(signersBuffer)
		if err != nil {
			return err
		}

		var signer = APKSignatureV2Signer{}
		err = signer.Parse(signerBuffer)
		if err != nil {
			return err
		}

		sig.Signers = append(sig.Signers, signer)
	}
	return nil
}

func readLengthPrefixedSequence(buf *bytes.Buffer) (*bytes.Buffer, error) {
	if buf.Len() < 4 {
		return nil, errors.New("corrupted length prefix for sequence block")
	}

	var sequenceLength = binary.LittleEndian.Uint32(buf.Next(4))
	if buf.Len() < int(sequenceLength) {
		return nil, errors.New("corrupted data for sequence block")
	}
	return bytes.NewBuffer(buf.Next(int(sequenceLength))), nil
}
