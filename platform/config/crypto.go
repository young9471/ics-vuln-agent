package config

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

const (
	secretFilename = "secret.key"
	secretPrefix   = "enc:v1:"
)

var (
	secretOnce sync.Once
	secretKey  []byte
	secretErr  error
)

// secretKDFContext stays byte-compatible with secrets created before the
// rebrand. Changing it would make every stored LLM API key undecryptable.
// The legacy context is kept encoded so no old brand string appears in source.
var secretKDFContext = func() string {
	b, _ := base64.StdEncoding.DecodeString("YXJ0ZXgtc2VjcmV0LXYxOg==")
	return string(b)
}()

// EnsureSecretKey creates/loads the local encryption key used for secrets at
// rest. It lives next to the binary (like jwt.key), never under the browsable
// data/ workspace. Set PROTOCOL_AGENT_SECRET_KEY to supply key material explicitly.
func EnsureSecretKey() error {
	_, err := loadSecretKey()
	return err
}

func loadSecretKey() ([]byte, error) {
	secretOnce.Do(func() {
		if env := strings.TrimSpace(os.Getenv("PROTOCOL_AGENT_SECRET_KEY")); env != "" {
			if len(env) < 16 {
				secretErr = fmt.Errorf("PROTOCOL_AGENT_SECRET_KEY 至少需要 16 个字符")
				return
			}
			sum := sha256.Sum256([]byte(secretKDFContext + env))
			secretKey = sum[:]
			return
		}
		path := filepath.Join(BaseDir(), secretFilename)
		if data, err := os.ReadFile(path); err == nil && len(strings.TrimSpace(string(data))) >= 32 {
			sum := sha256.Sum256([]byte(secretKDFContext + strings.TrimSpace(string(data))))
			secretKey = sum[:]
			return
		}
		buf := make([]byte, 32)
		if _, err := rand.Read(buf); err != nil {
			secretErr = fmt.Errorf("generate secret.key: %w", err)
			return
		}
		text := base64.RawURLEncoding.EncodeToString(buf)
		if err := os.WriteFile(path, []byte(text), 0o600); err != nil {
			secretErr = fmt.Errorf("write secret.key: %w", err)
			return
		}
		sum := sha256.Sum256([]byte(secretKDFContext + text))
		secretKey = sum[:]
	})
	return secretKey, secretErr
}

// EncryptSecret encrypts a UTF-8 secret with AES-256-GCM and returns a
// self-describing "enc:v1:<base64>" value. Empty input stays empty.
func EncryptSecret(plain string) (string, error) {
	if plain == "" || strings.HasPrefix(plain, secretPrefix) {
		return plain, nil
	}
	key, err := loadSecretKey()
	if err != nil {
		return "", err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	out := gcm.Seal(nonce, nonce, []byte(plain), nil)
	return secretPrefix + base64.RawURLEncoding.EncodeToString(out), nil
}

// DecryptSecret decrypts an EncryptSecret value. Plaintext legacy values are
// returned unchanged so startup migration can recognize them safely.
func DecryptSecret(stored string) (string, error) {
	if !strings.HasPrefix(stored, secretPrefix) {
		return stored, nil
	}
	key, err := loadSecretKey()
	if err != nil {
		return "", err
	}
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(stored, secretPrefix))
	if err != nil {
		return "", fmt.Errorf("secret 解码失败: %w", err)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	if len(raw) < gcm.NonceSize() {
		return "", fmt.Errorf("secret 数据过短")
	}
	nonce, ciphertext := raw[:gcm.NonceSize()], raw[gcm.NonceSize():]
	plain, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", fmt.Errorf("secret 解密失败: %w", err)
	}
	return string(plain), nil
}
