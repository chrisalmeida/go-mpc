package dkls23

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"testing"

	"github.com/stretchr/testify/require"
)

// testEncryptor implements SetupEncryptor using AES-256-GCM.
type testEncryptor struct {
	key []byte // 32 bytes
}

func newTestEncryptor() *testEncryptor {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		panic(err)
	}
	return &testEncryptor{key: key}
}

func (e *testEncryptor) Encrypt(plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(e.key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	return gcm.Seal(nonce, nonce, plaintext, nil), nil
}

func (e *testEncryptor) Decrypt(ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(e.key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	ns := gcm.NonceSize()
	if len(ciphertext) < ns {
		return nil, fmt.Errorf("ciphertext too short")
	}
	return gcm.Open(nil, ciphertext[:ns], ciphertext[ns:], nil)
}

func TestMarshalUnmarshalSetup(t *testing.T) {
	setups := fullSetup(t)
	for id, s := range setups {
		data, err := MarshalSetup(s)
		require.NoError(t, err, "party %d marshal", id)
		require.NotEmpty(t, data)

		got, err := UnmarshalSetup(data)
		require.NoError(t, err, "party %d unmarshal", id)
		require.Equal(t, s.MyID, got.MyID)
		require.True(t, s.Share.Equals(&got.Share), "party %d share", id)
		require.Equal(t, s.PubKey, got.PubKey)
		require.Equal(t, s.Threshold, got.Threshold)
		require.Equal(t, s.Epoch, got.Epoch)
		require.Equal(t, len(s.AliceBaseOT), len(got.AliceBaseOT))
		require.Equal(t, len(s.BobBaseOT), len(got.BobBaseOT))
		require.Equal(t, len(s.FZeroSeeds), len(got.FZeroSeeds))
	}
}

func TestMarshalEncryptedRoundTrip(t *testing.T) {
	setups := fullSetup(t)
	enc := newTestEncryptor()

	for id, s := range setups {
		ct, err := MarshalEncrypted(s, enc)
		require.NoError(t, err, "party %d encrypt", id)
		require.NotEmpty(t, ct)

		got, err := UnmarshalEncrypted(ct, enc)
		require.NoError(t, err, "party %d decrypt", id)
		require.Equal(t, s.MyID, got.MyID)
		require.True(t, s.Share.Equals(&got.Share))
		require.Equal(t, s.PubKey, got.PubKey)
	}
}

func TestUnmarshalEncryptedWrongKey(t *testing.T) {
	setups := fullSetup(t)
	enc1 := newTestEncryptor()
	enc2 := newTestEncryptor()

	ct, err := MarshalEncrypted(setups[1], enc1)
	require.NoError(t, err)

	_, err = UnmarshalEncrypted(ct, enc2)
	require.Error(t, err, "decrypting with wrong key should fail")
}

func TestUnmarshalSetupBadJSON(t *testing.T) {
	_, err := UnmarshalSetup([]byte("not json"))
	require.Error(t, err)
}

func TestUnmarshalSetupWrongVersion(t *testing.T) {
	setups := fullSetup(t)
	data, err := MarshalSetup(setups[1])
	require.NoError(t, err)

	// A missing version field must be rejected.
	_, err = UnmarshalSetup([]byte(`{"my_id":1,"all_ids":[1],"share":"","pub_key":"","threshold":1}`))
	require.Error(t, err)
	require.Contains(t, err.Error(), "version")

	// A future version must be rejected rather than misread: rewrite only the
	// version field of an otherwise valid document.
	var doc map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(data, &doc))
	require.JSONEq(t, "1", string(doc["version"]))
	doc["version"] = json.RawMessage("99")
	bumped, err := json.Marshal(doc)
	require.NoError(t, err)
	_, err = UnmarshalSetup(bumped)
	require.Error(t, err)
	require.Contains(t, err.Error(), "version 99")

	// The same document with the correct version still loads.
	doc["version"] = json.RawMessage("1")
	ok, err := json.Marshal(doc)
	require.NoError(t, err)
	_, err = UnmarshalSetup(ok)
	require.NoError(t, err)
}

func TestMarshalEncryptedEncryptError(t *testing.T) {
	setups := fullSetup(t)
	_, err := MarshalEncrypted(setups[1], &failingEncryptor{})
	require.Error(t, err)
	require.Contains(t, err.Error(), "encrypt")
}

func TestUnmarshalEncryptedDecryptError(t *testing.T) {
	_, err := UnmarshalEncrypted([]byte("data"), &failingEncryptor{})
	require.Error(t, err)
	require.Contains(t, err.Error(), "decrypt")
}

func TestMarshalEncryptedFunctional(t *testing.T) {
	t.Parallel()
	setups := fullSetup(t)
	enc := newTestEncryptor()

	// Encrypt, decrypt, then sign with the restored setup
	restored := make(map[int]*SignerSetup)
	for id, s := range setups {
		ct, err := MarshalEncrypted(s, enc)
		require.NoError(t, err)
		r, err := UnmarshalEncrypted(ct, enc)
		require.NoError(t, err)
		restored[id] = r
	}

	msg := []byte("encrypted persistence test")
	r, s := runSigning(t, restored, []int{1, 2, 3}, msg)
	verifyECDSA(t, restored[1].PubKey, msg, r, s)
}
