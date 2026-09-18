package hash

import (
	"encoding/hex"

	"golang.org/x/crypto/blake2b"
)

func blake2bHex(s string) string {
	h, err := blake2b.New256(nil)
	if err != nil {
		panic(err)
	}
	h.Write([]byte(s))
	return hex.EncodeToString(h.Sum(nil))
}
