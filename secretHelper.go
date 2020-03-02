package crypt

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"
)

const defaultPipelineWhitelist = ".+"

// SecretHelper is the interface for encrypting and decrypting secrets
type SecretHelper interface {
	Encrypt(unencryptedText, pipelineWhitelist string) (encryptedTextPlusNonce string, err error)
	Decrypt(encryptedTextPlusNonce, pipeline string) (decryptedText, pipelineWhitelist string, err error)
	EncryptEnvelope(unencryptedText, pipelineWhitelist string) (encryptedTextInEnvelope string, err error)
	DecryptEnvelope(encryptedTextInEnvelope, pipeline string) (decryptedText, pipelineWhitelist string, err error)
	DecryptAllEnvelopes(encryptedTextWithEnvelopes, pipeline string) (decryptedText string, err error)
	ReencryptAllEnvelopes(encryptedTextWithEnvelopes, pipeline string, base64encodedKey bool) (reencryptedText string, key string, err error)
	GenerateKey(numberOfBytes int, base64encodedKey bool) (key string, err error)
}

type secretHelperImpl struct {
	key              string
	base64encodedKey bool
}

// NewSecretHelper returns a new SecretHelper
func NewSecretHelper(key string, base64encodedKey bool) SecretHelper {

	return &secretHelperImpl{
		key:              key,
		base64encodedKey: base64encodedKey,
	}
}

func (sh *secretHelperImpl) getKey(key string, base64encodedKey bool) (keyBytes []byte, err error) {

	keyBytes = []byte(key)
	if base64encodedKey {
		keyBytes, err = base64.StdEncoding.DecodeString(key)
		if err != nil {
			return keyBytes, err
		}
	}

	return keyBytes, nil
}

func (sh *secretHelperImpl) Encrypt(unencryptedText, pipelineWhitelist string) (encryptedTextPlusNonce string, err error) {
	return sh.encryptWithKey(unencryptedText, pipelineWhitelist, sh.key, sh.base64encodedKey)
}

func (sh *secretHelperImpl) encryptWithKey(unencryptedText, pipelineWhitelist, key string, base64encodedKey bool) (encryptedTextPlusNonce string, err error) {

	// The key argument should be the AES key, either 16 or 32 bytes to select AES-128 or AES-256.
	keyBytes, err := sh.getKey(key, base64encodedKey)
	if err != nil {
		return
	}
	plaintext := []byte(unencryptedText)

	block, err := aes.NewCipher(keyBytes)
	if err != nil {
		return
	}

	// Never use more than 2^32 random nonces with a given key because of the risk of a repeat.
	nonce := make([]byte, 12)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return encryptedTextPlusNonce, err
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return
	}

	ciphertext := aesgcm.Seal(nil, nonce, plaintext, nil)

	encryptedTextPlusNonce = fmt.Sprintf("%v.%v", base64.URLEncoding.EncodeToString(nonce), base64.URLEncoding.EncodeToString(ciphertext))

	pipelineWhitelist = strings.TrimSpace(pipelineWhitelist)
	if pipelineWhitelist != "" && pipelineWhitelist != defaultPipelineWhitelist {
		cipherpipelinewhitelist := aesgcm.Seal(nil, nonce, []byte(pipelineWhitelist), nil)
		encryptedTextPlusNonce += fmt.Sprintf(".%v", base64.URLEncoding.EncodeToString(cipherpipelinewhitelist))
	}

	return
}

func (sh *secretHelperImpl) Decrypt(encryptedTextPlusNonce, pipeline string) (decryptedText, pipelineWhitelist string, err error) {

	return sh.decryptWithKey(encryptedTextPlusNonce, pipeline, sh.key, sh.base64encodedKey)
}

func (sh *secretHelperImpl) decryptWithKey(encryptedTextPlusNonce, pipeline string, key string, base64encodedKey bool) (decryptedText, pipelineWhitelist string, err error) {

	// get decryption key
	keyBytes, err := sh.getKey(key, base64encodedKey)
	if err != nil {
		return
	}
	block, err := aes.NewCipher(keyBytes)
	if err != nil {
		return
	}
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return
	}

	// split string on dots to get nonce, value and pipeline whitelist
	splittedStrings := strings.Split(encryptedTextPlusNonce, ".")
	if splittedStrings == nil || (len(splittedStrings) != 2 && len(splittedStrings) != 3) {
		err = errors.New("The encrypted text plus nonce doesn't split correctly")
		return
	}

	// get nonce
	nonceBase64 := splittedStrings[0]
	nonce, _ := base64.URLEncoding.DecodeString(nonceBase64)

	// get value
	valueBase64 := splittedStrings[1]
	valueEncrypted, _ := base64.URLEncoding.DecodeString(valueBase64)
	valueBytes, err := aesgcm.Open(nil, nonce, valueEncrypted, nil)
	if err != nil {
		return
	}
	decryptedText = string(valueBytes)

	if len(splittedStrings) == 2 {
		pipelineWhitelist = defaultPipelineWhitelist

		// no need to check pipeline against pipeline whitelist, since the default matches all pipelines
		return
	}

	// get pipeline whitelist if present
	pipelineWhitelistBase64 := splittedStrings[2]
	pipelineWhitelistEncrypted, _ := base64.URLEncoding.DecodeString(pipelineWhitelistBase64)
	pipelineWhitelistBytes, err := aesgcm.Open(nil, nonce, pipelineWhitelistEncrypted, nil)
	if err != nil {
		return
	}
	pipelineWhitelist = string(pipelineWhitelistBytes)

	// check if pipeline is matched by pipeline whitelist regular expression
	pattern := fmt.Sprintf("^%v$", pipelineWhitelist)
	validForPipeline, err := regexp.MatchString(pattern, pipeline)
	if err != nil {
		return
	}
	if !validForPipeline {
		return "", "", fmt.Errorf("Pipeline %v does not match regular expression ^%v$", pipeline, pipelineWhitelist)
	}

	return
}

func (sh *secretHelperImpl) EncryptEnvelope(unencryptedText, pipelineWhitelist string) (encryptedTextInEnvelope string, err error) {

	return sh.encryptEnvelopeWithKey(unencryptedText, pipelineWhitelist, sh.key, sh.base64encodedKey)
}

func (sh *secretHelperImpl) encryptEnvelopeWithKey(unencryptedText, pipelineWhitelist, key string, base64encodedKey bool) (encryptedTextInEnvelope string, err error) {

	encryptedText, err := sh.encryptWithKey(unencryptedText, pipelineWhitelist, key, base64encodedKey)
	if err != nil {
		return
	}
	encryptedTextInEnvelope = fmt.Sprintf("estafette.secret(%v)", encryptedText)

	return
}

func (sh *secretHelperImpl) DecryptEnvelope(encryptedTextInEnvelope, pipeline string) (decryptedText, pipelineWhitelist string, err error) {

	r, err := regexp.Compile(`^estafette\.secret\(([a-zA-Z0-9.=_-]+)\)$`)
	if err != nil {
		return
	}

	matches := r.FindStringSubmatch(encryptedTextInEnvelope)
	if matches == nil {
		return encryptedTextInEnvelope, defaultPipelineWhitelist, nil
	}

	decryptedText, pipelineWhitelist, err = sh.Decrypt(matches[1], pipeline)
	if err != nil {
		return
	}

	return
}

func (sh *secretHelperImpl) decryptEnvelopeInBytes(encryptedTextInEnvelope []byte, pipeline string) []byte {

	decryptedText, _, err := sh.DecryptEnvelope(string(encryptedTextInEnvelope), pipeline)
	if err != nil {
		return nil
	}

	return []byte(decryptedText)
}

func (sh *secretHelperImpl) DecryptAllEnvelopes(encryptedTextWithEnvelopes, pipeline string) (decryptedText string, err error) {

	r, err := regexp.Compile(`estafette\.secret\([a-zA-Z0-9.=_-]+\)`)
	if err != nil {
		return
	}

	decryptedText = string(r.ReplaceAllFunc([]byte(encryptedTextWithEnvelopes), func(in []byte) []byte {
		return sh.decryptEnvelopeInBytes(in, pipeline)
	}))

	return
}

func (sh *secretHelperImpl) GenerateKey(numberOfBytes int, base64encodedKey bool) (string, error) {

	key := make([]byte, numberOfBytes)

	_, err := rand.Read(key)
	if err != nil {
		return "", err
	}

	keyString := string(key)
	if base64encodedKey {
		keyString = base64.StdEncoding.EncodeToString(key)
	}

	return keyString, nil
}

func (sh *secretHelperImpl) ReencryptAllEnvelopes(encryptedTextWithEnvelopes, pipeline string, base64encodedKey bool) (reencryptedText string, key string, err error) {

	// generate 32 bytes key
	key, err = sh.GenerateKey(32, base64encodedKey)
	if err != nil {
		return encryptedTextWithEnvelopes, key, err
	}

	// scan for all secrets and replace them with new secret
	r, err := regexp.Compile(`estafette\.secret\([a-zA-Z0-9.=_-]+\)`)
	if err != nil {
		return
	}

	reencryptedText = string(r.ReplaceAllFunc([]byte(encryptedTextWithEnvelopes), func(encryptedTextInEnvelope []byte) []byte {

		decryptedText, pipelineWhitelist, err := sh.DecryptEnvelope(string(encryptedTextInEnvelope), pipeline)
		if err != nil {
			return nil
		}

		reencryptedTextInEnvelope, err := sh.encryptEnvelopeWithKey(decryptedText, pipelineWhitelist, key, base64encodedKey)
		if err != nil {
			return nil
		}

		return []byte(reencryptedTextInEnvelope)
	}))

	return reencryptedText, key, nil
}
