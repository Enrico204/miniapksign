package jarsigner

import (
	"bytes"
	"crypto/x509"
)

type APKSignatureV2SignedData struct {
	Digests              []APKSignatureV2Digest
	Certificates         []*x509.Certificate
	AdditionalAttributes []APKSignatureV2AdditionalAttribute
}

func (signedData *APKSignatureV2SignedData) Parse(buf *bytes.Buffer) error {
	// Digests
	digestsBuffer, err := readLengthPrefixedSequence(buf)
	if err != nil {
		return err
	}
	for digestsBuffer.Len() > 0 {
		digestBuffer, err := readLengthPrefixedSequence(digestsBuffer)
		if err != nil {
			return err
		}

		var digest = APKSignatureV2Digest{}
		err = digest.Parse(digestBuffer)
		if err != nil {
			return err
		}

		signedData.Digests = append(signedData.Digests, digest)
	}

	// Certificates
	certificatesBuffer, err := readLengthPrefixedSequence(buf)
	if err != nil {
		return err
	}
	for certificatesBuffer.Len() > 0 {
		certBuffer, err := readLengthPrefixedSequence(certificatesBuffer)
		if err != nil {
			return err
		}

		certificate, err := x509.ParseCertificate(certBuffer.Bytes())
		if err != nil {
			return err
		}

		signedData.Certificates = append(signedData.Certificates, certificate)
	}

	// Additional attributes
	additionalAttributesBuffer, err := readLengthPrefixedSequence(buf)
	if err != nil {
		return err
	}
	for additionalAttributesBuffer.Len() > 0 {
		attributeBuffer, err := readLengthPrefixedSequence(additionalAttributesBuffer)
		if err != nil {
			return err
		}

		var attribute = APKSignatureV2AdditionalAttribute{}
		err = attribute.Parse(attributeBuffer)
		if err != nil {
			return err
		}

		signedData.AdditionalAttributes = append(signedData.AdditionalAttributes, attribute)
	}
	return nil
}
