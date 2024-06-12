package cmd_test

import (
	"bytes"
	// "crypto/rand"
	// "crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"log"
	// "os"
	"strconv"
	"testing"

	"github.com/nart4hire/fingerprints/lib/extraction"
	"github.com/nart4hire/fingerprints/lib/helpers"
	"github.com/nart4hire/gofze/lib"
	// "github.com/nart4hire/goschnorr"
)

func TestCases(t *testing.T) {
	minutiaeList := [][]uint32{}
	for i := range 8 {
		// Read & Process Biometric Image
		_, m := helpers.LoadImage("../tc/106_"+ strconv.Itoa(i + 1) + ".jpg")
		minutiae := extraction.DetectionResult(m)
		// if len(minutiae.Minutia) == 0 {
		// 	log.Fatalf("Error in Minutiae Extraction: %v", "No Minutiae Detected")
		// }

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

		if len(minutiae.Minutia) > 10 {
			minutiaeList = append(minutiaeList, minutiaeUint32)
			log.Println("Appended  :\n" + strconv.Itoa(i))
		}
		// // Minutiae Fuzzy Extraction
		// fe := lib.NewDefaultFuzzy32Extractor(len(minutiaeUint32), 4)
		// key, helperz, err := fe.Gen(minutiaeHex)
		// if err != nil {
		// 	log.Fatalf("Error in Fuzzy Extraction: %v", err)
		// }
		// log.Println("Key       :\n", key)
		// // log.Println("Helpers   :\n", helpers)

		// keyBytes, err := hex.DecodeString(string(key))
		// if err != nil {
		// 	log.Fatalf("Error in Hex Decode: %v", err)
		// }

		// keyHash := sha256.Sum256(keyBytes)
	}
	log.Println("List: ", minutiaeList)
}