//nolint:forbidigo
package main

import (
	"fmt"
	apksigner "gitlab.com/enrico204/miniapksign"
	jarsigner2 "gitlab.com/enrico204/miniapksign/v2signature"
	"os"
)

func main() {
	if len(os.Args) != 2 {
		_, _ = fmt.Fprintf(os.Stderr, "Usage: %s <filename.apk>\n", os.Args[0])
		return
	}

	fp, err := os.Open(os.Args[1])
	if err != nil {
		panic(err)
	}

	stat, err := fp.Stat()
	if err != nil {
		panic(err)
	}

	var sig = jarsigner2.APKSignatureV2{}
	// TODO: signature verifier
	// Based on https://source.android.com/security/apksigning/v2.html
	blocks, err := apksigner.ReadSigningBlock(fp, stat.Size())
	if err != nil {
		panic(err)
	}

	for _, b := range blocks {
		switch b.ID {
		case apksigner.BlockIDAPKSignV2:
			fmt.Print("APK Signature Scheme v2 Block found, length: ")
			fmt.Println(b.Raw.Len())
			err = sig.Parse(b.Raw)
			if err != nil {
				panic(err)
			}
		case apksigner.BlockIDAPKSignV3:
			// TODO
		default:
			// Do nothing
		}
	}
	fmt.Println(sig)
	fmt.Println(sig.Signers[0].SignedData.Certificates[0].Issuer)
}
