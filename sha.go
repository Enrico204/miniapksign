package miniapksign

import (
	"crypto/sha1" //nolint:gosec // Unfortunately we need this primitive
	"crypto/sha256"
	"encoding/base64"
)

// SHA1Manifest returns the SHA1 digest as Base64 string (the same format that you find in the manifest)
func SHA1Manifest(blob []byte) string {
	var sha1digest = sha1.New() //nolint:gosec // Unfortunately we need this primitive
	_, _ = sha1digest.Write(blob)
	return base64.StdEncoding.EncodeToString(sha1digest.Sum(nil))
}

// SHA256Manifest returns the SHA256 digest as Base64 string (the same format that you find in the manifest)
func SHA256Manifest(blob []byte) string {
	var sha256digest = sha256.New()
	_, _ = sha256digest.Write(blob)
	return base64.StdEncoding.EncodeToString(sha256digest.Sum(nil))
}
