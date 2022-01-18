package miniapksign

import (
	"archive/zip"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	jarsigner "gitlab.com/enrico204/miniapksign/v2signature"
	"go.mozilla.org/pkcs7"
	"io"
	"io/ioutil"
	"regexp"
)

var signatureFileRegex = regexp.MustCompile(`^META-INF/.*\.(DSA|EC|RSA)$`)

// GetFirstSignerCertificate returns the certificate for the first signer of an APK/JAR.
// It looks for v1 signatures, if not found it looks for v2 and then v3
// For the moment it supports only v1 signers.
// Note: probably this algorithm is wrong, as we need to check signatures in backward (v4, v3, v2 and v1 as last resort)
// I need to ask this to F-Droid maintainers
func GetFirstSignerCertificate(file io.ReaderAt, size int64) (*x509.Certificate, error) {
	archive, err := zip.NewReader(file, size)
	if err != nil {
		return nil, err
	}

	var signatureFile *zip.File
	for _, f := range archive.File {
		if signatureFileRegex.MatchString(f.Name) {
			if signatureFile != nil {
				return nil, errors.New("multiple signature found in archive, not supported")
			}
			signatureFile = f
		}
	}
	if signatureFile != nil {
		// V1 signature detected
		fp, err := signatureFile.Open()
		if err != nil {
			return nil, fmt.Errorf("opening signature file: %w", err)
		}

		sigFileContent, err := ioutil.ReadAll(fp)
		if err != nil {
			return nil, fmt.Errorf("reading signature file: %w", err)
		}
		_ = fp.Close()

		p7, err := pkcs7.Parse(sigFileContent)
		if err != nil {
			return nil, fmt.Errorf("reading PKCS7: %w", err)
		}

		signer := p7.GetOnlySigner()
		if signer == nil {
			return nil, errors.New("no signer or multiple signer detected in v1 signature")
		}
		return signer, nil
	}

	blocks, err := ReadSigningBlock(file, size)
	if err != nil {
		panic(err)
	}

	var blockIndex = -1
	for idx, b := range blocks {
		if b.ID == BlockIDAPKSignV2 {
			blockIndex = idx
		}
	}
	if blockIndex > -1 {
		var sig = jarsigner.APKSignatureV2{}
		err = sig.Parse(blocks[blockIndex].Raw)
		if err != nil {
			return nil, fmt.Errorf("error reading v2 signature: %w", err)
		}

		if len(sig.Signers) > 0 && len(sig.Signers[0].SignedData.Certificates) > 0 {
			return sig.Signers[0].SignedData.Certificates[0], nil
		}
		return nil, errors.New("v2 signature doesn't have a certificate")
	}

	// TODO
	return nil, errors.New("v3 signature not supported yet")
}

func GetSHA256Fingerprint(file io.ReaderAt, size int64) (string, error) {
	signatureCertificate, err := GetFirstSignerCertificate(file, size)
	if err != nil {
		return "", err
	}

	var sha256digest = sha256.New()
	sha256digest.Write(signatureCertificate.Raw)
	return hex.EncodeToString(sha256digest.Sum(nil)), nil
}
