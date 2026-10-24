// Package shared provides utilities used by both signing examples.
package shared

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// AESEncryptor demonstrates envelope encryption: Key is a 32-byte wrapping key;
// every blob gets a fresh random data key. KeyID selects wrapping keys on import.
// PreviousKeys permits rotation without rewriting existing blobs immediately.
// Configure fields before use, assign a distinct ID when changing the wrapping
// key, and rotate before 2^32 encryptions per wrapping key, as required by
// cipher.NewGCMWithRandomNonce. AES/GCM timing depends on hardware support
// (Go crypto/aes/aes.go and crypto/cipher/gcm.go); it is not measured here.
// Key management remains the application's choice.
type AESEncryptor struct {
	Key          [32]byte
	KeyID        string
	PreviousKeys map[string][32]byte
}

func gcm(key []byte) (cipher.AEAD, error) {
	b, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCMWithRandomNonce(b)
}
func (e *AESEncryptor) Encrypt(plaintext []byte) ([]byte, error) {
	return e.EncryptContext(plaintext, nil)
}
func (e *AESEncryptor) Decrypt(blob []byte) ([]byte, error) { return e.DecryptContext(blob, nil) }

// EncryptContext authenticates the envelope header with the example's version
// and wrapping-key identifier. A fresh data key is wrapped for every blob.
func (e *AESEncryptor) EncryptContext(plaintext, aad []byte) ([]byte, error) {
	id := e.KeyID
	if id == "" {
		id = "local"
	}
	if len(id) > 65535 {
		return nil, fmt.Errorf("encryptor: key id too long")
	}
	header := make([]byte, 3+len(id))
	header[0] = 1
	binary.BigEndian.PutUint16(header[1:3], uint16(len(id)))
	copy(header[3:], id)
	associated := append(append([]byte(nil), header...), aad...)
	var dataKey [32]byte
	if _, err := rand.Read(dataKey[:]); err != nil {
		return nil, err
	}
	defer clear(dataKey[:])
	wrapping, err := gcm(e.Key[:])
	if err != nil {
		return nil, err
	}
	wrapped := wrapping.Seal(nil, nil, dataKey[:], associated)
	data, err := gcm(dataKey[:])
	if err != nil {
		return nil, err
	}
	return data.Seal(append(header, wrapped...), nil, plaintext, associated), nil
}

// DecryptContext rejects changed headers, wrapped data keys and ciphertext.
func (e *AESEncryptor) DecryptContext(blob, aad []byte) ([]byte, error) {
	if len(blob) < 3 || blob[0] != 1 {
		return nil, fmt.Errorf("encryptor: unsupported or truncated blob")
	}
	end := 3 + int(binary.BigEndian.Uint16(blob[1:3]))
	if end == 3 || len(blob) < end+60+28 {
		return nil, fmt.Errorf("encryptor: truncated key or ciphertext")
	}
	id := string(blob[3:end])
	current := e.KeyID
	if current == "" {
		current = "local"
	}
	key := e.Key
	if id != current {
		var ok bool
		key, ok = e.PreviousKeys[id]
		if !ok {
			return nil, fmt.Errorf("encryptor: unknown wrapping-key identifier")
		}
	}
	associated := append(append([]byte(nil), blob[:end]...), aad...)
	wrapping, err := gcm(key[:])
	clear(key[:])
	if err != nil {
		return nil, err
	}
	dataKey, err := wrapping.Open(nil, nil, blob[end:end+60], associated)
	if err != nil {
		return nil, err
	}
	defer clear(dataKey)
	data, err := gcm(dataKey)
	if err != nil {
		return nil, err
	}
	return data.Open(nil, nil, blob[end+60:], associated)
}

// LoadOrCreateKey loads an environment-supplied wrapping key; no key is written
// beside encrypted shares. The boolean reports an existing demo manifest.
// Legacy enc.key directories require explicit migration.
func LoadOrCreateKey(dir string) (*AESEncryptor, bool, error) {
	raw, err := hex.DecodeString(os.Getenv("MPC_WRAPPING_KEY"))
	if err != nil || len(raw) != 32 {
		return nil, false, fmt.Errorf("set MPC_WRAPPING_KEY to 64 hex characters (32 random bytes)")
	}
	defer clear(raw)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, false, err
	}
	if _, err := os.Stat(filepath.Join(dir, "enc.key")); err == nil {
		return nil, false, fmt.Errorf("legacy enc.key directory: migrate explicitly or choose a new MPC_DEMO_DIR")
	}
	enc := &AESEncryptor{KeyID: os.Getenv("MPC_WRAPPING_KEY_ID")}
	copy(enc.Key[:], raw)
	_, err = os.Stat(filepath.Join(dir, "manifest.json"))
	if err == nil {
		return enc, true, nil
	}
	if !os.IsNotExist(err) {
		return nil, false, err
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, false, err
	}
	if len(entries) > 0 {
		return nil, false, fmt.Errorf("incomplete demo directory without manifest; inspect it before recovery")
	}
	return enc, false, nil
}
func DemoDirectory() string {
	if dir := os.Getenv("MPC_DEMO_DIR"); dir != "" {
		return dir
	}
	return "shares"
}

// Manifest is public demo configuration. Production bindings must come from an
// authenticated key registry; an editable manifest is not a trust anchor.
type Manifest struct {
	Protocol  string
	PublicKey []byte
	Parties   []int
}

func SaveManifest(dir string, m Manifest) error {
	b, err := json.Marshal(m)
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, "manifest.json"), b, 0600)
}
func LoadManifest(dir string) (Manifest, error) {
	var m Manifest
	b, err := os.ReadFile(filepath.Join(dir, "manifest.json"))
	if err != nil {
		return m, err
	}
	err = json.Unmarshal(b, &m)
	return m, err
}
