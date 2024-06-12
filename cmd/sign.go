/*
Copyright © 2024 Nathanael

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
*/
package cmd

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"log"
	"os"

	"github.com/nart4hire/fingerprints/lib/extraction"
	"github.com/nart4hire/fingerprints/lib/helpers"
	"github.com/nart4hire/goschnorr"
	"github.com/spf13/cobra"

	"github.com/nart4hire/gofze/lib"
)

// signCmd represents the sign command
var signCmd = &cobra.Command{
	Use:   "sign",
	Short: "A brief description of your command",
	Long: `A longer description that spans multiple lines and likely contains examples
and usage of using your command. For example:

Cobra is a CLI library for Go that empowers applications.
This application is a tool to generate the needed files
to quickly create a Cobra application.`,
	Run: func(cmd *cobra.Command, args []string) {
		// Read File to be signed
		b, err := os.ReadFile(args[0])
		if err != nil {
			log.Fatalf("Error in Reading File: %v", err)
		}

		// Read & Process Biometric Image
		_, m := helpers.LoadImage(args[1])
		minutiae := extraction.DetectionResult(m)
		minutiaeUint32 := make([]uint32, len(minutiae.Minutia))
		for i := range minutiae.Minutia {
			minutia := lib.NewMinutia(&minutiae.Minutia[i])
			minutiaeUint32[i] = minutia.GetBuffer()
		}
		minutiaeBytes := new(bytes.Buffer)
		binary.Write(minutiaeBytes, binary.BigEndian, &minutiaeUint32)
		minutiaeHex := hex.EncodeToString(minutiaeBytes.Bytes())
		log.Println("Minutiae  :\n", minutiaeHex)

		// Minutiae Fuzzy Extraction
		fe := lib.NewDefaultFuzzy32Extractor(len(minutiaeUint32), 4)
		key, helpers, err := fe.Gen(minutiaeHex)
		if err != nil {
			log.Fatalf("Error in Fuzzy Extraction: %v", err)
		}
		log.Println("Key       :\n", key)
		log.Println("Helpers   :\n", helpers)

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
		log.Println("P         :\n", p)
		log.Println("Q         :\n", q)
		log.Println("G         :\n", g)
		log.Println("Signature :\n", sig)
		log.Println("Hash      :\n", hash)
		log.Println("Public Key:\n", pub)
	},
}

func init() {
	rootCmd.AddCommand(signCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// signCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// signCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}
