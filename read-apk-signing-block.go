package miniapksign

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

const APKSignBlockMagic = "APK Sig Block 42"
const (
	// BlockIDAPKSignV2 is a v2 signature block
	BlockIDAPKSignV2 = 0x7109871a

	// BlockIDAPKSignV3 is a v3 signature block
	BlockIDAPKSignV3 = 0xf05368c0

	// BlockIDAPKSignVerityPadding represent a block for padding (to block size multiple of 4096 bytes)
	BlockIDAPKSignVerityPadding = 0x42726577

	BlockIDAPKChannel = 0x71777777

	// BlockIDAPKDependencyInfo is a Google-encrypted dependencies metadata
	BlockIDAPKDependencyInfo = 0x504b4453

	// BlockIDAPKSignSourceStampV2 is a Google signature used to "improve security"
	BlockIDAPKSignSourceStampV2 = 0x6dff800d

	// BlockIDAPKSignSourceStampV1 is an older version of BlockIDAPKSignSourceStampV2
	BlockIDAPKSignSourceStampV1 = 0x2b09189e

	// BlockIDAPKGooglePlayMetadataFrosting are metadata from Google Play Store
	BlockIDAPKGooglePlayMetadataFrosting = 0x2146444e
)

type SigningBlock struct {
	ID  uint32
	Raw *bytes.Buffer
}

var ErrAPKSigningBlockNotFound = errors.New("APK Signing Block not found")

func ReadSigningBlock(reader io.ReaderAt, size int64) ([]SigningBlock, error) {
	// TODO: use a sliding buffer to allocate fewer bytes
	var maxRead int64 = 512 * 1024
	if size < maxRead {
		maxRead = size
	}
	var baseReadPosition = size - maxRead
	var buf = make([]byte, maxRead)

	p, err := reader.ReadAt(buf, baseReadPosition)
	if err != nil {
		return nil, fmt.Errorf("reading bytes from zip: %w", err)
	}
	buf = buf[:p]

	// Look for magic string
	var magicoffset = bytes.LastIndex(buf, []byte(APKSignBlockMagic))
	if magicoffset < 0 {
		return nil, ErrAPKSigningBlockNotFound
	} else if magicoffset < 8 {
		// TODO: internal buffer too low, we need to increase it and re-read the file
		return nil, errors.New("internal buffer too low")
	}

	// Magic string found, read the APK Signing block size
	var apkSigningBlockSize = binary.LittleEndian.Uint64(buf[magicoffset-8 : magicoffset])
	if apkSigningBlockSize > 1024*1024*10 {
		// Safety net: do not allocate and read more than 10MB
		return nil, errors.New("I kindly refuse to read more than 10MB of APK Signing Block")
	} else if uint64(magicoffset) < apkSigningBlockSize {
		// TODO: internal buffer too low, we need to increase it and re-read the file
		return nil, errors.New("internal buffer too low")
	}
	// The start of the block is before the uint64 of the length. However, the length contains both the magic and the
	// last length uint64
	var absoluteStartOfAPKSigningBlock = baseReadPosition + int64(uint64(magicoffset-8)-apkSigningBlockSize+16+8)

	// Verify: the 8-byte block before the signature block should be the same as the apkSigningBlockSize
	var apkSigningBlockSizeTopBuffer = make([]byte, 8)
	p, err = reader.ReadAt(apkSigningBlockSizeTopBuffer, absoluteStartOfAPKSigningBlock-8)
	if err != nil {
		return nil, fmt.Errorf("reading bytes from zip: %w", err)
	} else if p != 8 {
		return nil, errors.New("can't read the first block of the APK Signing Block")
	}
	var apkSigningBlockSizeTop = binary.LittleEndian.Uint64(apkSigningBlockSizeTopBuffer)
	if apkSigningBlockSize != apkSigningBlockSizeTop {
		return nil, errors.New("APK Signing Block length mismatch")
	}

	// Read the APK signing block (the length contains the uint64 of the length and the magic)
	var apkSigningBlock = make([]byte, apkSigningBlockSize-(8+16))
	p, err = reader.ReadAt(apkSigningBlock, absoluteStartOfAPKSigningBlock)
	if err != nil {
		return nil, fmt.Errorf("reading bytes from zip: %w", err)
	} else if uint64(p) < (apkSigningBlockSize - (8 + 16)) {
		return nil, errors.New("read error: APK Signing Block is too short")
	}

	return parseSigningBlock(bytes.NewBuffer(apkSigningBlock))
}

// parseSigningBlock reads all items in the APK Signing block
func parseSigningBlock(apkSigningBlock *bytes.Buffer) ([]SigningBlock, error) {
	var ret []SigningBlock
	for apkSigningBlock.Len() > 0 {
		// Safety check
		if apkSigningBlock.Len() < 8+4 {
			return nil, errors.New("invalid signing block size")
		}

		var pairLength = binary.LittleEndian.Uint64(apkSigningBlock.Next(8))

		var id = binary.LittleEndian.Uint32(apkSigningBlock.Next(4))

		if pairLength > 0 {
			var value = make([]byte, int(pairLength-4))
			p, err := apkSigningBlock.Read(value)
			if err != nil {
				return nil, err
			} else if p != int(pairLength-4) {
				return nil, errors.New("corrupted block")
			}

			ret = append(ret, SigningBlock{
				ID:  id,
				Raw: bytes.NewBuffer(value),
			})
		} else {
			ret = append(ret, SigningBlock{
				ID: id,
			})
		}
	}
	return ret, nil
}
