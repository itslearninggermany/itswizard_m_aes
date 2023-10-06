package itswizard_m_aes

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"io"
	math "math/rand"
	"time"
)

var letterRunes = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")

func CreateAESString(n int) string {
	math.Seed(time.Now().UnixNano())
	b := make([]rune, n)
	for i := range b {
		b[i] = letterRunes[math.Intn(len(letterRunes))]
	}
	return string(b)
}

func Encrypt(key []byte, message string) (encmess string, err error) {
	plainText := []byte(message)

	block, err := aes.NewCipher(key)
	if err != nil {
		return
	}

	//IV needs to be unique, but doesn't have to be secure.
	//It's common to put it at the beginning of the ciphertext.
	cipherText := make([]byte, aes.BlockSize+len(plainText))
	iv := cipherText[:aes.BlockSize]
	if _, err = io.ReadFull(rand.Reader, iv); err != nil {
		return
	}

	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(cipherText[aes.BlockSize:], plainText)

	//returns to base64 encoded string
	encmess = base64.URLEncoding.EncodeToString(cipherText)
	return
}

func Decrypt(key []byte, securemess string) (decodedmess string, err error) {
	cipherText, err := base64.URLEncoding.DecodeString(securemess)
	if err != nil {
		return
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return
	}

	if len(cipherText) < aes.BlockSize {
		err = errors.New("Ciphertext block size is too short!")
		return
	}

	iv := cipherText[:aes.BlockSize]
	cipherText = cipherText[aes.BlockSize:]

	stream := cipher.NewCFBDecrypter(block, iv)
	// XORKeyStream can work in-place if the two arguments are the same.
	stream.XORKeyStream(cipherText, cipherText)

	decodedmess = string(cipherText)
	return
}

/*
type AesCode struct {
	Key []byte `json:"key"`
}

func NewAes() (*AesCode, error) {
	aesCode := new(AesCode)
	key := make([]byte, 32)
	_, err := rand.Read(key)
	if err != nil {
		return nil, err
	}
	aesCode.Key = key
	return aesCode, nil
}

func LoadAes(filepath string) (aes AesCode, err error) {
	b, err := ioutil.ReadFile(filepath)
	if err != nil {
		return aes, err
	}
	err = json.Unmarshal(b, &aes)
	if err != nil {
		return aes, err
	}
	return aes, err
}

func (p *AesCode) GetAesKey() []byte {
	return p.Key
}

func (p *AesCode) SaveAes(filepath string) error {
	b, err := json.Marshal(p)
	if err != nil {
		return err
	}
	err = ioutil.WriteFile(filepath, b, 600)
	if err != nil {
		return err
	}
	return nil
}

func (p *AesCode) Encryption(toDecrypt []byte) ([]byte, error) {
	c, err := aes.NewCipher(p.Key)
	// if there are any errors, handle them
	if err != nil {
		return []byte(""), err
	}
	// gcm or Galois/Counter Mode, is a mode of operation
	// for symmetric key cryptographic block ciphers
	// - https://en.wikipedia.org/wiki/Galois/Counter_Mode
	gcm, err := cipher.NewGCM(c)
	// if any error generating new GCM
	// handle them
	if err != nil {
		return []byte(""), err
	}

	// creates a new byte array the size of the nonce
	// which must be passed to Seal
	nonce := make([]byte, gcm.NonceSize())
	// populates our nonce with a cryptographically secure
	// random sequence
	_, err = io.ReadFull(rand.Reader, nonce)
	if err != nil {
		return []byte(""), err
	}

	// here we encrypt our text using the Seal function
	// Seal encrypts and authenticates plaintext, authenticates the
	// additional data and appends the result to dst, returning the updated
	// slice. The nonce must be NonceSize() bytes long and unique for all
	// time, for a given key.
	return gcm.Seal(nonce, nonce, toDecrypt, nil), nil
}

func Encryption(key []byte, toDecrypt []byte) ([]byte, error) {
	c, err := aes.NewCipher(key)
	// if there are any errors, handle them
	if err != nil {
		return []byte(""), err
	}
	// gcm or Galois/Counter Mode, is a mode of operation
	// for symmetric key cryptographic block ciphers
	// - https://en.wikipedia.org/wiki/Galois/Counter_Mode
	gcm, err := cipher.NewGCM(c)
	// if any error generating new GCM
	// handle them
	if err != nil {
		return []byte(""), err
	}

	// creates a new byte array the size of the nonce
	// which must be passed to Seal
	nonce := make([]byte, gcm.NonceSize())
	// populates our nonce with a cryptographically secure
	// random sequence
	_, err = io.ReadFull(rand.Reader, nonce)
	if err != nil {
		return []byte(""), err
	}

	// here we encrypt our text using the Seal function
	// Seal encrypts and authenticates plaintext, authenticates the
	// additional data and appends the result to dst, returning the updated
	// slice. The nonce must be NonceSize() bytes long and unique for all
	// time, for a given key.
	return gcm.Seal(nonce, nonce, toDecrypt, nil), nil
}

func (p *AesCode) Decryption(toEncrypt []byte) ([]byte, error) {
	c, err := aes.NewCipher(p.Key)
	if err != nil {
		return []byte(""), err
	}

	gcm, err := cipher.NewGCM(c)
	if err != nil {
		return []byte(""), err
	}

	nonceSize := gcm.NonceSize()
	if len(toEncrypt) < nonceSize {
		return []byte(""), errors.New("len(toEncrypt) < nonceSize")
	}

	nonce, ciphertext := toEncrypt[:nonceSize], toEncrypt[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return []byte(""), err
	}
	return plaintext, err
}

func Decryption(key []byte, toEncrypt []byte) ([]byte, error) {
	c, err := aes.NewCipher(key)
	if err != nil {
		return []byte(""), err
	}

	gcm, err := cipher.NewGCM(c)
	if err != nil {
		return []byte(""), err
	}

	nonceSize := gcm.NonceSize()
	if len(toEncrypt) < nonceSize {
		return []byte(""), errors.New("len(toEncrypt) < nonceSize")
	}

	nonce, ciphertext := toEncrypt[:nonceSize], toEncrypt[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return []byte(""), err
	}
	return plaintext, err
}

*/
