//nolint:forbidigo
package main

import (
	"fmt"
	apksigner "gitlab.com/enrico204/miniapksign"
	"os"
)

func main() {
	if len(os.Args) != 2 {
		_, _ = fmt.Fprintf(os.Stderr, "Usage: %s <filename.apk>\n", os.Args[0])
		return
	}

	// Open APK file
	apkfile, err := os.Open(os.Args[1])
	if err != nil {
		panic(err)
	}
	defer func() { _ = apkfile.Close() }()

	// Get APK file info
	apkstat, err := apkfile.Stat()
	if err != nil {
		panic(err)
	}

	// Get the SHA256Fingerprint
	fingerprint, err := apksigner.GetSHA256Fingerprint(apkfile, apkstat.Size())
	if err != nil {
		panic(err)
	}

	fmt.Println(fingerprint)
}
