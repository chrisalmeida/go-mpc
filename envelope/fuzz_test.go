package envelope_test

import (
	"bytes"
	"slices"
	"testing"

	"github.com/chrisalmeida/go-mpc/envelope"
)

func FuzzOpen(f *testing.F) {
	// No mutable spy counters are shared with fuzz workers.
	fixture := encryptor(f)
	seed, err := envelope.Seal(fixture, context(), []byte("disposable checkpoint"))
	if err != nil {
		f.Fatal(err)
	}
	f.Add(seed)
	f.Add([]byte{})
	f.Add([]byte{2, 0, 0})
	f.Fuzz(func(t *testing.T, data []byte) {
		before := slices.Clone(data)
		enc := &legacyEncryptor{aead: fixture.aead}
		plain, err := envelope.Open(enc, context(), data)
		if !bytes.Equal(before, data) {
			t.Fatal("Open modified its input")
		}
		if err != nil {
			if plain != nil {
				t.Fatal("rejection released plaintext")
			}
			return
		}
		peek, err := envelope.Peek(data)
		if err != nil {
			t.Fatal(err)
		}
		if peek.OperationID != context().OperationID || peek.Protocol != envelope.FROST {
			t.Fatal("Open accepted another context")
		}
		sealed, err := envelope.Seal(enc, context(), plain)
		if err != nil {
			t.Fatal(err)
		}
		restored, err := envelope.Open(enc, context(), sealed)
		if err != nil || !bytes.Equal(plain, restored) {
			t.Fatal("accepted payload did not round trip")
		}
	})
}

func FuzzPeek(f *testing.F) {
	f.Add(frame(rawContext(fields()), []byte{1}))
	f.Add([]byte{})
	f.Add([]byte{1, 255, 255})
	f.Fuzz(func(t *testing.T, data []byte) {
		before := slices.Clone(data)
		ctx, err := envelope.Peek(data)
		if !bytes.Equal(before, data) {
			t.Fatal("Peek modified its input")
		}
		if err != nil {
			return
		}
		// Re-encoding must produce the exact same canonical header, even
		// though Peek cannot authenticate the original ciphertext.
		enc := encryptor(t)
		sealed, err := envelope.Seal(enc, ctx, nil)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(data[:headerSize(data)], sealed[:headerSize(sealed)]) {
			t.Fatal("noncanonical context accepted")
		}
	})
}
