package waf

import (
	"crypto/sha256"
	"encoding/base64"
	"math/big"
	"strconv"

	"golang.org/x/crypto/scrypt"
)

const bandwidthChallenge = "ha9faaffd31b4d5ede2a2e19d2d7fd525f66fee61911511960dcbb52d3c48ce25"

var bandwidthSizes = map[int]int{
	1: 1024,
	2: 10 * 1024,
	3: 100 * 1024,
	4: 1 * 1048576,
	5: 10 * 1048576,
}

func computeSHA256PoW(input, checksum string, difficulty int) string {
	base := []byte(input + checksum)
	shift := uint(256 - difficulty)
	buf := make([]byte, 0, len(base)+32)
	for nonce := int64(0); ; nonce++ {
		buf = append(buf[:0], base...)
		buf = strconv.AppendInt(buf, nonce, 10)
		sum := sha256.Sum256(buf)
		asInt := new(big.Int).SetBytes(sum[:])
		if new(big.Int).Rsh(asInt, shift).Sign() == 0 {
			return strconv.FormatInt(nonce, 10)
		}
	}
}

func computeScrypt(challenge, checksum string, difficulty int) (string, error) {
	prefix := []byte(challenge + checksum)
	salt := []byte(checksum)
	shift := uint(128 - difficulty)
	buf := make([]byte, 0, len(prefix)+32)
	for nonce := int64(0); ; nonce++ {
		buf = append(buf[:0], prefix...)
		buf = strconv.AppendInt(buf, nonce, 10)
		hash, err := scrypt.Key(buf, salt, 128, 8, 1, 16)
		if err != nil {
			return "", err
		}
		asInt := new(big.Int).SetBytes(hash)
		if new(big.Int).Rsh(asInt, shift).Sign() == 0 {
			return strconv.FormatInt(nonce, 10), nil
		}
	}
}

func computeBandwidth(difficulty int) string {
	n, ok := bandwidthSizes[difficulty]
	if !ok {
		n = 1024
	}
	buf := make([]byte, n)
	return base64.StdEncoding.EncodeToString(buf)
}
