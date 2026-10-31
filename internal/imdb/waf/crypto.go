package waf

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"sync"
)

var wafKey = mustHex("6f71a512b1e035eaab53d8be73120d3fb68a0ca346b9560aab3e5cdf753d5e98")

var (
	aeadOnce sync.Once
	aeadImpl cipher.AEAD
	aeadErr  error
)

func aead() (cipher.AEAD, error) {
	aeadOnce.Do(func() {
		block, err := aes.NewCipher(wafKey)
		if err != nil {
			aeadErr = err
			return
		}
		aeadImpl, aeadErr = cipher.NewGCM(block)
	})
	return aeadImpl, aeadErr
}

func encryptPayload(plaintext string) (string, error) {
	gcm, err := aead()
	if err != nil {
		return "", err
	}
	iv := make([]byte, 12)
	if _, err := rand.Read(iv); err != nil {
		return "", err
	}
	sealed := gcm.Seal(nil, iv, []byte(plaintext), nil)
	tag := sealed[len(sealed)-16:]
	ciphertext := sealed[:len(sealed)-16]
	return fmt.Sprintf("%s::%s::%s",
		base64.StdEncoding.EncodeToString(iv),
		hex.EncodeToString(tag),
		hex.EncodeToString(ciphertext),
	), nil
}

func mustHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}
