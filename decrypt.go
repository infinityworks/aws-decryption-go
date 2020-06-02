package decrypt

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha512"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"

	"golang.org/x/crypto/hkdf"
)

// Decrypter takes a ciphertext and decrypts it.
type Decrypter interface {
	Decrypt([]byte) ([]byte, error)
}

// Decrypt is a Decrypter for AWS Encryption SDK encoded payloads.
type Decrypt struct {
	pk *rsa.PrivateKey
}

// New creates a new SDK Decrypter given a private key pem file.
func New(privKey []byte) (d Decrypt, err error) {
	// Extract the PEM-encoded data block.
	pem, _ := pem.Decode(privKey)
	if pem == nil {
		return d, fmt.Errorf("bad key data: %s", "not PEM-encoded")
	}
	// Decode the RSA private key.
	pk, err := x509.ParsePKCS8PrivateKey(pem.Bytes)
	if err != nil {
		return d, fmt.Errorf("bad private key: %s", err)
	}
	rsapk, ok := pk.(*rsa.PrivateKey)
	if !ok {
		return d, fmt.Errorf("supplied key is not an RSA private key")
	}
	return Decrypt{rsapk}, nil
}

// Decrypt does a decrypt of an AWS SDK payload.
func (d *Decrypt) Decrypt(in []byte) (out []byte, err error) {
	msg, err := newMessage(in)
	if err != nil {
		return out, err
	}
	// Use private key to decrypt khdf secrets.
	secrets := make([][]byte, len(msg.header.keys))
	for i := range secrets {
		secrets[i], err = rsa.DecryptOAEP(sha512.New(), rand.Reader, d.pk, msg.header.keys[i].key, nil)
		if err != nil {
			return
		}
	}
	// Decrypt each frame separately.
	out = make([]byte, 0)
	hkdfInfo := msg.getHKDFInfo()
	for i, f := range msg.body.frames {
		// Generate AES keys using hkdf.
		hkdf := hkdf.New(sha512.New384, secrets[i], nil, hkdfInfo)
		key := make([]byte, len(secrets[i]))
		_, err = io.ReadFull(hkdf, key)
		if err != nil {
			return
		}
		// Prepare for AES decryption using key.
		var block cipher.Block
		block, err = aes.NewCipher(key)
		if err != nil {
			return
		}
		var aesgcm cipher.AEAD
		aesgcm, err = cipher.NewGCM(block)
		if err != nil {
			return
		}
		// Decrypt frame.
		var frame []byte
		frame, err = aesgcm.Open(nil, f.iv, append(f.content, f.authTag...), msg.getAAD(i))
		if err != nil {
			return
		}
		out = append(out, frame...)
	}
	return out, nil
}
