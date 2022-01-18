// Package apksigner apksigner implements a simple JAR signer (v1 signature for APKs)
// TODO: implements v2/v3/v4 android signatures
package miniapksign

import (
	"archive/zip"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"fmt"
	"go.mozilla.org/pkcs7"
)

type FileSpec struct {
	Name         string
	SHA1Digest   string
	SHA256Digest string
}

// SignWriter will create the V1 signature in the ZIP file. It requires the list of files within the ZIP file, together
// with their digest
func SignWriter(archive *zip.Writer, zipFiles []FileSpec, certificate *x509.Certificate, privateKey *rsa.PrivateKey) error {
	// Prepare files
	manifestContent := "Manifest-Version: 1.0\nCreated-By: fdroid-repo-manager apksigner\n\n"
	for _, f := range zipFiles {
		manifestContent += fmt.Sprintf("Name: %s\n", f.Name)
		switch {
		case f.SHA1Digest != "":
			manifestContent += fmt.Sprintf("SHA1-Digest: %s\n", f.SHA1Digest)
		case f.SHA256Digest != "":
			manifestContent += fmt.Sprintf("SHA256-Digest: %s\n", f.SHA256Digest)
		default:
			return errors.New("some digest are missing, can't sign")
		}
		manifestContent += "\n"
	}

	signatureManifestContent := fmt.Sprintf(
		"Signature-Version: 1.0\nCreated-By: fdroid-repo-manager apksigner\nSHA1-Digest-Manifest: %s\nSHA256-Digest-Manifest: %s\n\n",
		SHA1Manifest([]byte(manifestContent)), SHA256Manifest([]byte(manifestContent)),
	)
	for _, f := range zipFiles {
		signatureManifestContent += fmt.Sprintf("Name: %s\n", f.Name)
		switch {
		case f.SHA1Digest != "":
			signatureManifestContent += fmt.Sprintf("SHA1-Digest: %s\n", f.SHA1Digest)
		case f.SHA256Digest != "":
			signatureManifestContent += fmt.Sprintf("SHA256-Digest: %s\n", f.SHA256Digest)
		default:
			return errors.New("some digest are missing, can't sign")
		}
		signatureManifestContent += "\n"
	}

	signedManifestData, err := RSASignAndDetach([]byte(signatureManifestContent), certificate, privateKey)
	if err != nil {
		return err
	}

	// Write Manifest
	manifest, _ := archive.Create("META-INF/MANIFEST.MF")
	_, err = manifest.Write([]byte(manifestContent))
	if err != nil {
		return err
	}

	// Write Signature manifest (plain text)
	signatureManifest, _ := archive.Create("META-INF/SIG.SF")
	_, err = signatureManifest.Write([]byte(signatureManifestContent))
	if err != nil {
		return err
	}
	// TODO: add optional manifest SHA1/SHA256 digest

	// Write signature of the "Signature manifest"
	signedManifest, _ := archive.Create("META-INF/SIG.RSA")
	_, err = signedManifest.Write(signedManifestData)
	if err != nil {
		return err
	}

	return archive.Close()
}

// RSASignAndDetach create an RSA signature and remove the signed content from the signature
func RSASignAndDetach(content []byte, cert *x509.Certificate, privkey *rsa.PrivateKey) (signed []byte, err error) {
	toBeSigned, err := pkcs7.NewSignedData(content)
	if err != nil {
		err = fmt.Errorf("cannot initialize signed data: %w", err)
		return
	}
	if err = toBeSigned.AddSigner(cert, privkey, pkcs7.SignerInfoConfig{}); err != nil {
		err = fmt.Errorf("cannot add signer: %w", err)
		return
	}

	toBeSigned.Detach()

	signed, err = toBeSigned.Finish()
	if err != nil {
		err = fmt.Errorf("cannot finish signing data: %w", err)
		return
	}

	return signed, nil
}
