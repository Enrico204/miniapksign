package jarsigner

import "bytes"

type APKSignatureV2Signer struct {
	SignedData APKSignatureV2SignedData
	Signatures []APKSignatureV2Signature
	PublicKey  []byte
}

func (signer *APKSignatureV2Signer) Parse(buf *bytes.Buffer) error {
	// Signed data
	signedDataBuffer, err := readLengthPrefixedSequence(buf)
	if err != nil {
		return err
	}

	err = signer.SignedData.Parse(signedDataBuffer)
	if err != nil {
		return err
	}

	// Signatures
	signaturesBuffer, err := readLengthPrefixedSequence(buf)
	if err != nil {
		return err
	}
	for signaturesBuffer.Len() > 0 {
		signatureBuffer, err := readLengthPrefixedSequence(signaturesBuffer)
		if err != nil {
			return err
		}

		var signature = APKSignatureV2Signature{}
		err = signature.Parse(signatureBuffer)
		if err != nil {
			return err
		}

		signer.Signatures = append(signer.Signatures, signature)
	}

	// Public key
	publicKeyBuffer, err := readLengthPrefixedSequence(buf)
	if err != nil {
		return err
	}
	signer.PublicKey = publicKeyBuffer.Bytes()
	return nil
}
