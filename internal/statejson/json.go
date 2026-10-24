// Package statejson validates the canonical JSON schemas used by private-state
// envelopes. Legacy plaintext import APIs retain their original behavior.
package statejson

import (
	"bytes"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"io"
)

// Decode rejects duplicate fields, unknown/missing fields and noncanonical field
// values by comparing the decoded value's encoding with the original JSON tree.
// Whitespace and object field ordering are immaterial. Decode into a fresh value:
// callers publish it only after all validation succeeds. The comparison uses
// crypto/subtle.ConstantTimeCompare (Go 1.26.1 crypto/internal/fips140/subtle);
// JSON parsing and serialization are not claimed to be constant-time.
func Decode(data []byte, value any) error {
	d := json.NewDecoder(bytes.NewReader(data))
	if err := scan(d); err != nil {
		return err
	}
	if _, err := d.Token(); err != io.EOF {
		return errors.New("state JSON: trailing data")
	}
	if err := json.Unmarshal(data, value); err != nil {
		return err
	}
	canonical, err := json.Marshal(value)
	if err != nil {
		return err
	}
	defer clear(canonical)
	before, err := normalize(data)
	if err != nil {
		return err
	}
	defer clear(before)
	after, err := normalize(canonical)
	if err != nil {
		return err
	}
	defer clear(after)
	if subtle.ConstantTimeCompare(before, after) != 1 {
		return errors.New("state JSON: noncanonical or unknown fields")
	}
	return nil
}

func normalize(data []byte) ([]byte, error) {
	d := json.NewDecoder(bytes.NewReader(data))
	d.UseNumber()
	var tree any
	if err := d.Decode(&tree); err != nil {
		return nil, err
	}
	return json.Marshal(tree)
}

func scan(d *json.Decoder) error {
	t, err := d.Token()
	if err != nil {
		return err
	}
	switch t {
	case json.Delim('{'):
		seen := make(map[string]bool)
		for d.More() {
			key, err := d.Token()
			if err != nil {
				return err
			}
			s, ok := key.(string)
			if !ok || seen[s] {
				return errors.New("state JSON: duplicate or invalid field")
			}
			seen[s] = true
			if err := scan(d); err != nil {
				return err
			}
		}
		_, err = d.Token()
	case json.Delim('['):
		for d.More() {
			if err := scan(d); err != nil {
				return err
			}
		}
		_, err = d.Token()
	}
	return err
}
