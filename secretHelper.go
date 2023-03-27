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

var (
	// ErrRestrictedSecret is thrown if a restricted secret for another pipeline is encountered
	ErrRestrictedSecret = errors.New("This secret is restricted to another pipeline")
)

// DefaultPipelineAllowList is the regular expression that allows any pipeline to decrypt a secret
const DefaultPipelineAllowList = ".*"

// SecretEnvelopeRegex is the regular expression to match an estafette secret envelope
const SecretEnvelopeRegex = `estafette\.secret\(([a-zA-Z0-9.=_-]+)\)`

// SecretHelper is the interface for encrypting and decrypting secrets
type SecretHelper interface {
	Encrypt(unencryptedText, pipelineAllowList string) (encryptedTextPlusNonce string, err error)
	Decrypt(encryptedTextPlusNonce, pipeline string) (decryptedText, pipelineAllowList string, err error)
	EncryptEnvelope(unencryptedText, pipelineAllowList string) (encryptedTextInEnvelope string, err error)
	DecryptEnvelope(encryptedTextInEnvelope, pipeline string) (decryptedText, pipelineAllowList string, err error)
	DecryptAllEnvelopes(encryptedTextWithEnvelopes, pipeline string) (decryptedText string, err error)
	ReencryptAllEnvelopes(encryptedTextWithEnvelopes, pipeline string, base64encodedKey bool) (reencryptedText string, key string, err error)
	GenerateKey(numberOfBytes int, base64encodedKey bool) (key string, err error)
	GetAllSecretEnvelopes(input string) (envelopes []string, err error)
	GetAllSecrets(input string) (secrets []string, err error)
	GetAllSecretValues(input, pipeline string) (values []string, err error)
	GetInvalidRestrictedSecrets(input, pipeline string) (invalidSecrets []string, err error)
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

func (sh *secretHelperImpl) Encrypt(unencryptedText, pipelineAllowList string) (encryptedTextPlusNonce string, err error) {
	return sh.encryptWithKey(unencryptedText, pipelineAllowList, sh.key, sh.base64encodedKey)
}

func (sh *secretHelperImpl) encryptWithKey(unencryptedText, pipelineAllowList, key string, base64encodedKey bool) (encryptedTextPlusNonce string, err error) {

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

	pipelineAllowList = strings.TrimSpace(pipelineAllowList)
	if pipelineAllowList != "" && pipelineAllowList != DefaultPipelineAllowList {
		cipherpipelinewhitelist := aesgcm.Seal(nil, nonce, []byte(pipelineAllowList), nil)
		encryptedTextPlusNonce += fmt.Sprintf(".%v", base64.URLEncoding.EncodeToString(cipherpipelinewhitelist))
	}

	return
}

func (sh *secretHelperImpl) Decrypt(encryptedTextPlusNonce, pipeline string) (decryptedText, pipelineAllowList string, err error) {
	return sh.decrypt(encryptedTextPlusNonce, pipeline, true)
}

func (sh *secretHelperImpl) decrypt(encryptedTextPlusNonce, pipeline string, failOnRestrictError bool) (decryptedText, pipelineAllowList string, err error) {
	return sh.decryptWithKey(encryptedTextPlusNonce, pipeline, sh.key, sh.base64encodedKey, failOnRestrictError)
}

func (sh *secretHelperImpl) decryptWithKey(encryptedTextPlusNonce, pipeline string, key string, base64encodedKey, failOnRestrictError bool) (decryptedText, pipelineAllowList string, err error) {

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

	// get pipeline whitelist if present
	pipelineAllowList = DefaultPipelineAllowList
	if len(splittedStrings) == 3 {
		pipelineAllowListBase64 := splittedStrings[2]
		pipelineAllowListEncrypted, _ := base64.URLEncoding.DecodeString(pipelineAllowListBase64)
		pipelineAllowListBytes, err := aesgcm.Open(nil, nonce, pipelineAllowListEncrypted, nil)
		if err != nil {
			return "", "", err
		}
		pipelineAllowList = string(pipelineAllowListBytes)
	}

	// check if pipeline is matched by pipeline whitelist regular expression
	if failOnRestrictError {
		pattern := fmt.Sprintf("^%v$", pipelineAllowList)
		validForPipeline, innerErr := regexp.MatchString(pattern, pipeline)
		if innerErr != nil {
			return "", "", innerErr
		}
		if !validForPipeline {
			pattern = fmt.Sprintf("^github.com/.*/%s$", strings.Split(pipelineAllowList, "/")[2])
			validForPipeline, innerErr = regexp.MatchString(pattern, pipeline)
			if innerErr != nil {
				return "", "", innerErr
			}
			if !validForPipeline {
				return "", "", ErrRestrictedSecret
			}
		}
	}

	// get value
	valueBase64 := splittedStrings[1]
	valueEncrypted, _ := base64.URLEncoding.DecodeString(valueBase64)
	valueBytes, err := aesgcm.Open(nil, nonce, valueEncrypted, nil)
	if err != nil {
		return
	}
	decryptedText = string(valueBytes)

	return
}

func (sh *secretHelperImpl) EncryptEnvelope(unencryptedText, pipelineAllowList string) (encryptedTextInEnvelope string, err error) {

	return sh.encryptEnvelopeWithKey(unencryptedText, pipelineAllowList, sh.key, sh.base64encodedKey)
}

func (sh *secretHelperImpl) encryptEnvelopeWithKey(unencryptedText, pipelineAllowList, key string, base64encodedKey bool) (encryptedTextInEnvelope string, err error) {

	encryptedText, err := sh.encryptWithKey(unencryptedText, pipelineAllowList, key, base64encodedKey)
	if err != nil {
		return
	}
	encryptedTextInEnvelope = fmt.Sprintf("estafette.secret(%v)", encryptedText)

	return
}

func (sh *secretHelperImpl) DecryptEnvelope(encryptedTextInEnvelope, pipeline string) (decryptedText, pipelineAllowList string, err error) {
	return sh.decryptEnvelope(encryptedTextInEnvelope, pipeline, true)
}

func (sh *secretHelperImpl) decryptEnvelope(encryptedTextInEnvelope, pipeline string, failOnRestrictError bool) (decryptedText, pipelineAllowList string, err error) {

	r, err := regexp.Compile(fmt.Sprintf("^%v$", SecretEnvelopeRegex))
	if err != nil {
		return
	}

	matches := r.FindStringSubmatch(encryptedTextInEnvelope)
	if matches == nil {
		return encryptedTextInEnvelope, DefaultPipelineAllowList, nil
	}

	decryptedText, pipelineAllowList, err = sh.decrypt(matches[1], pipeline, failOnRestrictError)
	if err != nil {
		return
	}

	return
}

func (sh *secretHelperImpl) decryptEnvelopeInBytes(encryptedTextInEnvelope []byte, pipeline string) ([]byte, error) {

	decryptedText, _, err := sh.DecryptEnvelope(string(encryptedTextInEnvelope), pipeline)
	if err != nil {
		return nil, err
	}

	return []byte(decryptedText), nil
}

func (sh *secretHelperImpl) DecryptAllEnvelopes(encryptedTextWithEnvelopes, pipeline string) (decryptedText string, err error) {

	r, err := regexp.Compile(SecretEnvelopeRegex)
	if err != nil {
		return
	}

	var decryptErr error
	decryptedText = string(r.ReplaceAllFunc([]byte(encryptedTextWithEnvelopes), func(in []byte) []byte {
		bytes, innerErr := sh.decryptEnvelopeInBytes(in, pipeline)
		if innerErr != nil {
			decryptErr = innerErr
		}
		return bytes
	}))
	if decryptErr != nil {
		return decryptedText, decryptErr
	}

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
	r, err := regexp.Compile(SecretEnvelopeRegex)
	if err != nil {
		return
	}

	reencryptedText = string(r.ReplaceAllFunc([]byte(encryptedTextWithEnvelopes), func(encryptedTextInEnvelope []byte) []byte {

		decryptedText, pipelineAllowList, err := sh.decryptEnvelope(string(encryptedTextInEnvelope), pipeline, false)
		if err != nil {
			return nil
		}

		reencryptedTextInEnvelope, err := sh.encryptEnvelopeWithKey(decryptedText, pipelineAllowList, key, base64encodedKey)
		if err != nil {
			return nil
		}

		return []byte(reencryptedTextInEnvelope)
	}))

	return reencryptedText, key, nil
}

func (sh *secretHelperImpl) GetAllSecretEnvelopes(input string) (envelopes []string, err error) {

	r, err := regexp.Compile(SecretEnvelopeRegex)
	if err != nil {
		return
	}

	matches := r.FindAllStringSubmatch(input, -1)
	if matches != nil {
		for _, m := range matches {
			if len(m) > 1 {
				envelopes = append(envelopes, m[0])
			}
		}
	}

	return
}

func (sh *secretHelperImpl) GetAllSecrets(input string) (secrets []string, err error) {

	r, err := regexp.Compile(SecretEnvelopeRegex)
	if err != nil {
		return
	}

	matches := r.FindAllStringSubmatch(input, -1)
	if matches != nil {
		for _, m := range matches {
			if len(m) > 1 {
				secrets = append(secrets, m[1])
			}
		}
	}

	return
}

func (sh *secretHelperImpl) GetAllSecretValues(input, pipeline string) (values []string, err error) {

	r, err := regexp.Compile(SecretEnvelopeRegex)
	if err != nil {
		return
	}

	matches := r.FindAllStringSubmatch(input, -1)
	if matches != nil {
		for _, m := range matches {
			if len(m) > 1 {
				decryptedText, _, err := sh.Decrypt(m[1], pipeline)
				if err != nil {
					return []string{}, err
				}
				values = append(values, decryptedText)
			}
		}
	}

	return
}

func (sh *secretHelperImpl) GetInvalidRestrictedSecrets(input, pipeline string) (invalidSecrets []string, err error) {

	r, err := regexp.Compile(SecretEnvelopeRegex)
	if err != nil {
		return
	}

	matches := r.FindAllStringSubmatch(input, -1)
	if matches != nil {
		for _, m := range matches {
			if len(m) > 1 {
				_, _, err := sh.Decrypt(m[1], pipeline)
				if err != nil && errors.Is(err, ErrRestrictedSecret) {
					invalidSecrets = append(invalidSecrets, m[0])
				}
			}
		}
	}

	if len(invalidSecrets) > 0 {
		return invalidSecrets, ErrRestrictedSecret
	}

	return
}
