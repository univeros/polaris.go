// Package strictjson decodes a whole byte slice as one JSON value.
package strictjson

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
)

// Decode decodes data, one JSON value and nothing after it but white space, into out, numbers as
// json.Number where out takes any. json.Decoder.Decode alone reads the first value and ignores the
// rest, so a signed payload could carry what its verifier never read.
func Decode(data []byte, out any) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	if err := dec.Decode(out); err != nil {
		return err
	}
	if _, err := dec.Token(); err != io.EOF {
		return errors.New("data after the JSON value")
	}
	return nil
}
