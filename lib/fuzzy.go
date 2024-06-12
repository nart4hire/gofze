package lib

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"hash"
	"math"

	"golang.org/x/crypto/pbkdf2"
	"golang.org/x/exp/constraints"
)

type Key string // Hex Encoded 

type Number interface {
	constraints.Unsigned
}

type Helpers[T Number] struct {
	ciphers		[][]T
	masks		[][]T
	nonces		[][]T
}

type fuzzyextractor struct {
	hash			func() hash.Hash
	securityLength	int
	nonceLength		int
	blockLength		int
	hammingError	int
	reproduceError	float64
	numHelpers		int
}

type FuzzyExtractor[T Number] interface {
	Gen(value string) (Key, *Helpers[T], error)
	Rep(value string, helper *Helpers[T]) (Key, error)
}

func sum[T Number](input ...T) int {
	result := 0
	for _, b := range input {
		result += int(b)
	}
	return result
}

func NewFuzzyExtractor(blockLength, hammingError int,  reproduceError float64, securityLength, nonceLength int) FuzzyExtractor[byte] {
	return &fuzzyextractor{
		hash: sha256.New,
		securityLength: securityLength,
		nonceLength: nonceLength,
		blockLength: blockLength,
		hammingError: hammingError,
		reproduceError: reproduceError,
		numHelpers: getNumHelpers(8, blockLength, hammingError, reproduceError),
	}
}

func NewDefaultFuzzyExtractor(blockLength, hammingError int) FuzzyExtractor[byte] {
	return &fuzzyextractor{
		hash: sha256.New,
		securityLength: 2,
		nonceLength: 16,
		blockLength: blockLength,
		hammingError: hammingError,
		reproduceError: 0.001,
		numHelpers: getNumHelpers(8, blockLength, hammingError, 0.001),
	}
}

func getNumHelpers(blockSize, blockLength, hammingError int, reproduceError float64) int {
	n := float64(blockLength * blockSize)
	c := float64(hammingError) / math.Log(n)
	return int(math.Round(math.Pow(n, c) * math.Log2(float64(2) / reproduceError)))
}

func (fz *fuzzyextractor) Gen(value string) (Key, *Helpers[byte], error) {
	val, err := hex.DecodeString(value)
	if err != nil {
		return "", nil, err
	}

	if len(val) != fz.blockLength {
		return "", nil, errors.New("gofze/lib/fuzzy.go: invalid value length")
	}

	key := make([]byte, fz.blockLength)
	rand.Read(key)
	pad := make([]byte, fz.securityLength)
	keyPad := append(key, pad...)

	nonces  := make([][]byte, fz.numHelpers)
	masks   := make([][]byte, fz.numHelpers)
	vectors := make([][]byte, fz.numHelpers)
	digests := make([][]byte, fz.numHelpers)
	ciphers := make([][]byte, fz.numHelpers)

	for i := range fz.numHelpers {
		nonces[i] = make([]byte, fz.nonceLength)
		rand.Read(nonces[i])
		masks[i] = make([]byte, fz.blockLength)
		rand.Read(masks[i])
		vectors[i] = make([]byte, fz.blockLength)
		for j := range fz.blockLength {
			vectors[i][j] = val[j] & masks[i][j]
		}
		digests[i] = pbkdf2.Key(vectors[i], nonces[i], 1, fz.blockLength + fz.securityLength, fz.hash)
		ciphers[i] = make([]byte, fz.blockLength + fz.securityLength)
		for j := range fz.blockLength + fz.securityLength {
			ciphers[i][j] = digests[i][j] ^ keyPad[j]
		}
	}

	return Key(hex.EncodeToString(key)), &Helpers[byte]{
		ciphers: ciphers,
		masks: masks,
		nonces: nonces,
	}, nil
}

func (fz *fuzzyextractor) Rep(value string, helper *Helpers[byte]) (Key, error) {
	val, err := hex.DecodeString(value)
	if err != nil {
		return "", err
	}

	if len(val) != fz.blockLength {
		return "", errors.New("gofze/lib/fuzzy.go: invalid value length")
	}

	ciphers := helper.ciphers
	masks := helper.masks
	nonces := helper.nonces
	vectors := make([][]byte, fz.numHelpers)
	digests := make([][]byte, fz.numHelpers)
	plains := make([][]byte, fz.numHelpers)

	for i := range fz.numHelpers {
		vectors[i] = make([]byte, fz.blockLength)
		for j := range fz.blockLength {
			vectors[i][j] = masks[i][j] & val[j]
		}
		digests[i] = pbkdf2.Key(vectors[i], nonces[i], 1, fz.blockLength + fz.securityLength, fz.hash)
		plains[i] = make([]byte, fz.blockLength + fz.securityLength)
		for j := range fz.blockLength + fz.securityLength {
			plains[i][j] = digests[i][j] ^ ciphers[i][j]
		}
		if sum(plains[i][fz.blockLength:]...) == 0 {
			return Key(hex.EncodeToString(plains[i][:fz.blockLength])), nil
		}
	}

	return "", errors.New("gofze/lib/fuzzy.go: unable to reproduce key")
}