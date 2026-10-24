package statejson

import (
	"encoding/json"
	"errors"
	"testing"
)

type document struct {
	Value   string `json:"value"`
	Numbers []int  `json:"numbers"`
}
type badMarshal struct{}

func (*badMarshal) MarshalJSON() ([]byte, error) { return nil, errors.New("marshal failure") }

func TestStrictDecodeRejectsAmbiguousAndNoncanonicalDocuments(t *testing.T) {
	for _, input := range []string{`{"value":"a","numbers":[1,2]}`, " { \"numbers\": [1,2], \"value\": \"a\" } "} {
		var got document
		if err := Decode([]byte(input), &got); err != nil {
			t.Fatal(err)
		}
		if got.Value != "a" || len(got.Numbers) != 2 {
			t.Fatal(got)
		}
	}
	for _, input := range []string{``, `null`, `{`, `[]`, `{"value":"a","value":"b","numbers":[]}`, `{"value":"a","numbers":[1,]}`, `{"value":"a","numbers":[],"other":1}`, `{"value":"a"}`, `{"value":"a","numbers":[]} {}`, `{"value":4,"numbers":[]}`, `{"value":"a","numbers":[9007199254740993.0]}`, `{"value":"a","numbers":[{"x":1,"x":2}]}`} {
		var got document
		if err := Decode([]byte(input), &got); err == nil {
			t.Fatalf("accepted %s", input)
		}
	}
	// UseNumber prevents rounding integer payloads above 2^53 during comparison.
	var wide struct {
		Value int64 `json:"value"`
	}
	if err := Decode([]byte(`{"value":9007199254740993}`), &wide); err != nil {
		t.Fatal(err)
	}
	if err := Decode([]byte(`{}`), &badMarshal{}); err == nil {
		t.Fatal("ignored marshaler error")
	}
	if _, err := normalize([]byte(`{`)); err == nil {
		t.Fatal("normalized invalid JSON")
	}
	var object map[string]json.RawMessage
	if err := Decode([]byte(`{"outer":{"a":1,"a":2}}`), &object); err == nil {
		t.Fatal("nested duplicate")
	}
}
