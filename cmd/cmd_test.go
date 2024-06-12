package cmd_test

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"log"
	"os"
	"testing"

	"github.com/nart4hire/fingerprints/lib/extraction"
	"github.com/nart4hire/fingerprints/lib/helpers"
	"github.com/nart4hire/gofze/lib"
	"github.com/nart4hire/goschnorr"
)

func TestPipeline(t *testing.T) {
	// Read File to be signed
	b, err := os.ReadFile("../tc/test.pdf")
	if err != nil {
		log.Fatalf("Error in Reading File: %v", err)
	}

	// Read & Process Biometric Image
	_, m := helpers.LoadImage("../tc/103_6.jpg")
	minutiae := extraction.DetectionResult(m)
	if len(minutiae.Minutia) == 0 {
		log.Fatalf("Error in Minutiae Extraction: %v", "No Minutiae Detected")
	}

	minutiaeUint32 := make([]uint32, len(minutiae.Minutia))
	for i := range minutiae.Minutia {
		minutia := lib.NewMinutia(&minutiae.Minutia[i])
		minutiaeUint32[i] = minutia.GetBuffer()
	}
	minutiaeBytes := new(bytes.Buffer)
	binary.Write(minutiaeBytes, binary.BigEndian, &minutiaeUint32)
	log.Println(minutiaeBytes.Bytes())
	minutiaeHex := hex.EncodeToString(minutiaeBytes.Bytes())
	log.Println("Minutiae  :\n" + minutiaeHex)

	// Minutiae Fuzzy Extraction
	fe := lib.NewDefaultFuzzy32Extractor(len(minutiaeUint32), 4)
	key, helperz, err := fe.Gen(minutiaeHex)
	if err != nil {
		log.Fatalf("Error in Fuzzy Extraction: %v", err)
	}
	log.Println("Key       :\n", key)
	// log.Println("Helpers   :\n", helpers)

	keyBytes, err := hex.DecodeString(string(key))
	if err != nil {
		log.Fatalf("Error in Hex Decode: %v", err)
	}

	keyHash := sha256.Sum256(keyBytes)

	// Use as Scnorr Private Key
	s, err := schnorr.NewSchnorr(rand.Reader, sha256.New())
	if err != nil {
		log.Fatalf("Error in Schnorr Library: %v", err)
	}

	pub, err := s.GenFromPriv(keyHash[:])
	if err != nil {
		log.Fatalf("Error in GenerateKeyPair: %v", err)
	}

	sig, hash, err := s.Sign(keyHash[:], string(b))
	if err != nil {
		log.Fatalf("Error in Sign: %v", err)
	}

	p, q, g := s.GetParams()
	log.Println("P         :", p)
	log.Println("Q         :", q)
	log.Println("G         :", g)
	log.Println("Signature :", hex.EncodeToString(sig))
	log.Println("Hash      :", hex.EncodeToString(hash))
	log.Println("Public Key:", hex.EncodeToString(pub))

	// Verify Signature
	if !s.Verify(pub, sig, hash, string(b)) {
		log.Fatalf("Error in Verify: %v", "Invalid Signature")
	}

	// Verify Fingerprint
	_, mR := helpers.LoadImage("../tc/103_7.jpg")
	minutiaeR := extraction.DetectionResult(mR)
	if len(minutiae.Minutia) == 0 {
		log.Fatalf("Error in Minutiae Extraction: %v", "No Minutiae Detected")
	}

	minutiaeRUint32 := make([]uint32, len(minutiaeR.Minutia))
	for i := range minutiaeR.Minutia {
		minutiaR := lib.NewMinutia(&minutiaeR.Minutia[i])
		minutiaeRUint32[i] = minutiaR.GetBuffer()
	}
	minutiaeRBytes := new(bytes.Buffer)
	binary.Write(minutiaeRBytes, binary.BigEndian, &minutiaeRUint32)
	log.Println(minutiaeRBytes.Bytes())
	minutiaeRHex := hex.EncodeToString(minutiaeRBytes.Bytes())
	log.Println("Minutiae  :\n" + minutiaeRHex)

	keyR, err := fe.Rep(minutiaeRHex, helperz)
	if err != nil {
		log.Fatalf("Error in Fuzzy Extraction: %v", err)
	}
	log.Println("Key       :\n", keyR)

	if key != keyR {
		log.Fatalf("Error in Fuzzy Extraction: %v", "Invalid Fingerprint")
	}
}