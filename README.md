# aws-decryption-go
Decrypt KMS-formatted data using a custom private key.

This repo implements part of the [AWS Encryption SDK spec](https://docs.aws.amazon.com/encryption-sdk/latest/developer-guide/message-format.html) in go. It is presently limitted in scope:
* Decryption only
* Framed data body only
* Algorithm Suite 0x0378 only (see [this spec page](https://docs.aws.amazon.com/encryption-sdk/latest/developer-guide/algorithms-reference.html))

This is sufficient to decrypt encrypted customer input generated by the Amazon Connect platform.

## Usage

```go
func main () {
    key, err := ioutil.ReadFile("./private.key")
    if err != nil {
        log.Fatalf("error reading key file: %s", err)
    }
    ciphertext, err := ioutil.ReadFile("./ciphertext_base64")
    if err != nil {
        log.Fatalf("error reading key file: %s", err)
    }

    kms, err := decrypt.NewKMS([]byte(key))
	if err != nil {
		log.Fatalf("error creating decrypter: %s", err)
	}
	dataBytes, err := base64.StdEncoding.DecodeString(ciphertext)
	if err != nil {
		log.Fatalf("error decoding base64 ciphertext: %s", err)
	}
	result, err := kms.Decrypt(dataBytes)
	if err != nil {
		log.Fatalf("error decrypting data: %s", err)
    }
    fmt.Println("decrypted data: %s", string(result))
}
```