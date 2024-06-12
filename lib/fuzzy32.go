package lib

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"golang.org/x/crypto/pbkdf2"
)

type fuzzy32extractor fuzzyextractor

func NewFuzzy32Extractor(blockLength, hammingError int,  reproduceError float64, securityLength, nonceLength int) FuzzyExtractor[uint32] {
	return &fuzzy32extractor{
		hash: sha256.New,
		securityLength: securityLength,
		nonceLength: nonceLength,
		blockLength: blockLength,
		hammingError: hammingError,
		reproduceError: reproduceError,
		numHelpers: getNumHelpers(32, blockLength, hammingError, reproduceError),
	}
}

func NewDefaultFuzzy32Extractor(blockLength, hammingError int) FuzzyExtractor[uint32] {
	return &fuzzy32extractor{
		hash: sha256.New,
		securityLength: 2,
		nonceLength: 16,
		blockLength: blockLength,
		hammingError: hammingError,
		reproduceError: 0.001,
		numHelpers: getNumHelpers(32, blockLength, hammingError, 0.001),
	}
}

func (fz *fuzzy32extractor) Gen(value string) (Key, *Helpers[uint32], error) {
	val, err := hex.DecodeString(value)
	if err != nil {
		return "", nil, err
	}

	if len(val) != fz.blockLength * 4 {
		return "", nil, errors.New("gofze/lib/fuzzy32.go: invalid value length")
	}

	val32 := make([]uint32, fz.blockLength)
	binary.Read(bytes.NewReader(val), binary.BigEndian, &val32)

	key := make([]byte, fz.blockLength * 4)
	key32 := make([]uint32, fz.blockLength)
	rand.Read(key)
	binary.Read(bytes.NewReader(key), binary.BigEndian, &key32)

	pad := make([]uint32, fz.securityLength)
	keyPad := append(key32, pad...)

	nonces  := make([][]uint32, fz.numHelpers)
	masks   := make([][]uint32, fz.numHelpers)
	vectors := make([][]uint32, fz.numHelpers)
	digests := make([][]uint32, fz.numHelpers)
	ciphers := make([][]uint32, fz.numHelpers)

	for i := range fz.numHelpers {
		nonce8 := make([]byte, fz.nonceLength * 4)
		nonces[i] = make([]uint32, fz.nonceLength)
		rand.Read(nonce8)
		binary.Read(bytes.NewReader(nonce8), binary.BigEndian, &nonces[i])

		mask8 := make([]byte, fz.blockLength * 4)
		masks[i] = make([]uint32, fz.blockLength)
		rand.Read(mask8)
		binary.Read(bytes.NewReader(mask8), binary.BigEndian, &masks[i])

		vectors[i] = make([]uint32, fz.blockLength)
		for j := range fz.blockLength {
			vectors[i][j] = val32[j] & masks[i][j]
		}
		vector8 := new(bytes.Buffer)
		binary.Write(vector8, binary.BigEndian, &vectors[i])

		digest8 := pbkdf2.Key(vector8.Bytes(), nonce8, 1, (fz.blockLength + fz.securityLength) * 4, fz.hash)
		digests[i] = make([]uint32, fz.blockLength + fz.securityLength)
		binary.Read(bytes.NewReader(digest8), binary.BigEndian, &digests[i])

		ciphers[i] = make([]uint32, fz.blockLength + fz.securityLength)
		for j := range fz.blockLength + fz.securityLength {
			ciphers[i][j] = digests[i][j] ^ keyPad[j]
		}
	}

	return Key(hex.EncodeToString(key)), &Helpers[uint32]{
		ciphers: ciphers,
		masks: masks,
		nonces: nonces,
	}, nil
}

func (fz *fuzzy32extractor) Rep(value string, helper *Helpers[uint32]) (Key, error) {
	val, err := hex.DecodeString(value)
	if err != nil {
		return "", err
	}

	if len(val) != fz.blockLength * 4 {
		return "", errors.New("gofze/lib/fuzzy32.go: invalid value length")
	}

	val32 := make([]uint32, fz.blockLength)
	binary.Read(bytes.NewReader(val), binary.BigEndian, &val32)

	ciphers := helper.ciphers
	masks := helper.masks
	nonces := helper.nonces
	vectors := make([][]uint32, fz.numHelpers)
	digests := make([][]uint32, fz.numHelpers)
	plains := make([][]uint32, fz.numHelpers)

	for i := range fz.numHelpers {
		vectors[i] = make([]uint32, fz.blockLength)
		for j := range fz.blockLength {
			vectors[i][j] = masks[i][j] & val32[j]
		}
		vector8 := new(bytes.Buffer)
		binary.Write(vector8, binary.BigEndian, &vectors[i])

		nonce8 := new(bytes.Buffer)
		binary.Write(nonce8, binary.BigEndian, &nonces[i])

		digest8 := pbkdf2.Key(vector8.Bytes(), nonce8.Bytes(), 1, (fz.blockLength + fz.securityLength) * 4, fz.hash)
		digests[i] = make([]uint32, fz.blockLength + fz.securityLength)
		binary.Read(bytes.NewReader(digest8), binary.BigEndian, &digests[i])

		plains[i] = make([]uint32, fz.blockLength + fz.securityLength)
		for j := range fz.blockLength + fz.securityLength {
			plains[i][j] = digests[i][j] ^ ciphers[i][j]
		}
		if sum(plains[i][fz.blockLength:]...) == 0 {
			plain8 := new(bytes.Buffer)
			binary.Write(plain8, binary.BigEndian, plains[i][:fz.blockLength])
			return Key(hex.EncodeToString(plain8.Bytes())), nil
		}
	}

	return "", errors.New("gofze/lib/fuzzy32.go: unable to reproduce key")
}