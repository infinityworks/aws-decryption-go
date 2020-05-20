package decrypt

import "fmt"

type algMode string

const (
	algModeGCM algMode = "GCM"
)

type algName string

const (
	algNameGCM algName = "AES"
)

type algKDA string

const (
	algKDAHKDFWithSHA384 algKDA = "HKDF with SHA-384"
)

type algSA string

const (
	algSAECDSAWithP384AndSHA384 algSA = "ECDSA with P-384 and SHA-384"
)

type algorithm struct {
	id         uint16
	name       algName
	keyLen     uint64
	algMode    algMode
	ivLen      uint64
	authTagLen uint64
	algKDA     algKDA
	algSA      algSA
}

// https://docs.aws.amazon.com/encryption-sdk/latest/developer-guide/algorithms-reference.html
var (
	alg0378 = algorithm{0x0378, algNameGCM, 256, algModeGCM, 12, 16, algKDAHKDFWithSHA384, algSAECDSAWithP384AndSHA384}
)

func getAlgorithmByID(id uint16) (algorithm, error) {
	switch id {
	case 0x0378:
		return alg0378, nil
	default:
		return algorithm{}, fmt.Errorf("unhandled algorithm: %d", id)
	}

}
