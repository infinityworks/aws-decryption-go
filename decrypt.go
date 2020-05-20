package decrypt

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"io"

	"golang.org/x/crypto/hkdf"
)

// CipherText is a byte array that is encrypted in some way.
type CipherText []byte

// Decrypter takes a ciphertext and decrypts it.
type Decrypter interface {
	Decrypt(CipherText) ([]byte, error)
}

// KMS is a Decrypter for KMS encoded payloads.
type KMS struct {
	pk *rsa.PrivateKey
}

// NewKMS creates a new KMS Decrypter given a private key pem file.
func NewKMS(privKey []byte) (d KMS, err error) {
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
	return KMS{rsapk}, nil
}

// Decrypt does a decrypt of a KMS payload.
func (d *KMS) Decrypt(in CipherText) (out []byte, err error) {
	msg, err := newKMSMessage(in)
	if err != nil {
		return out, err
	}
	// Use private key to decrypt khdf secrets.
	secrets := make([][]byte, len(msg.header.keys))
	for i := range secrets {
		fmt.Println(base64.StdEncoding.EncodeToString(msg.header.keys[i].key))
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
		fmt.Printf("%x\n", msg.getAAD(i))
		fmt.Printf("%x\n", []byte{0xd5, 0xb6, 0xbf, 0x3d, 0x58, 0x97, 0x23, 0x89, 0x7b, 0x70, 0xda, 0x01, 0x5f, 0x5d, 0x63, 0xed, 0x41, 0x57, 0x53, 0x4b, 0x4d, 0x53, 0x45, 0x6e, 0x63, 0x72, 0x79, 0x70, 0x74, 0x69, 0x6f, 0x6e, 0x43, 0x6c, 0x69, 0x65, 0x6e, 0x74, 0x20, 0x46, 0x69, 0x6e, 0x61, 0x6c, 0x20, 0x46, 0x72, 0x61, 0x6d, 0x65, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08})
		frame, err = aesgcm.Open(nil, f.iv, append(f.content, f.authTag...), msg.getAAD(i))
		if err != nil {
			return
		}
		out = append(out, frame...)
	}
	return out, nil
}
