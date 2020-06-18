// Copyright 2016 Google Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package v1

import (
	"bytes"
	"crypto/sha256"
	"io"
	"io/ioutil"
	"testing"
)

var password = []byte("test")
var salt = make([]byte, saltSize)
var hmacKey = []byte{108, 34, 19, 46, 17, 200, 213, 245, 243, 57, 134, 76, 114, 236, 133, 105, 61, 16, 81, 186, 171, 90, 118, 84, 121, 145, 49, 160, 41, 116, 175, 21}
var aesKey = []byte{122, 207, 56, 234, 212, 67, 99, 125, 149, 229, 186, 218, 134, 62, 198, 250, 43, 188, 167, 183, 253, 233, 102, 38, 235, 243, 43, 66, 40, 112, 145, 209}

// TestKeys tests that the keys function hasn't changed and produces the expected keys.
func TestKeys(t *testing.T) {
	a, b, err := keys(password, salt, int(scryptIterations))
	if err != nil {
		t.Errorf("keys(%v, %v) => %q; want nil", password, salt, err)
	}
	if !bytes.Equal(a, aesKey) {
		t.Errorf("keys(%v, %v) => aesKey = %v; want %v", password, salt, a, aesKey)
	}
	if !bytes.Equal(b, hmacKey) {
		t.Errorf("keys(%v, %v) => hmacKey = %v; want %v", password, salt, b, hmacKey)
	}
}

// TestRoundTrip tests several size sets of data going through the encrypt/decrypt
// to make sure they come out the same.
func TestRoundTrip(t *testing.T) {
	spasswords := []string{
		"",
		"test",
		"a",
		"      ",
	}
	for _, x := range []int{13, 400} {
		rp, err := randBytes(x)
		if err != nil {
			t.Fatalf("randBytes(%d) => err", x)
		}
		spasswords = append(spasswords, string(rp))
	}
	sizes := []int{24, 1024, 15872, 16364, 16384, 16394, 16896, 66560}
	for _, spass := range spasswords {
		password := []byte(spass)
		for _, size := range sizes {
			t.Logf("Testing file of size: %db, with password: %s", size, password)
			b, err := randBytes(size)
			if err != nil {
				t.Errorf("randBytes(%d) => %q; want nil", size, err)
				continue
			}
			encReader, err := newEncryptReader(bytes.NewReader(b), password, salt, 1024)
			if err != nil {
				t.Errorf("NewEncryptReader() => %q; want nil", err)
				continue
			}
			cipher, err := ioutil.ReadAll(encReader)
			if err != nil {
				t.Errorf("ioutil.ReadAll(*EncryptReader) => %q; want nil", err)
				continue
			}
			decReader, err := NewDecryptReader(bytes.NewReader(cipher), password)
			if err != nil {
				t.Errorf("NewDecryptReader() => %q; want nil", err)
				continue
			}
			plain, err := ioutil.ReadAll(decReader)
			decReader.Close()
			if err != nil {
				t.Errorf("ioutil.ReadAll(*DecryptReader) => %q; want nil", err)
				continue
			}
			if !bytes.Equal(b, plain) {
				t.Errorf("Encrypt/Decrypt of file size %d, resulted in different values", size)
			}
		}
	}
}

func TestHash(t *testing.T) {
	sizes := []int{24, 1024, 15872, 16364, 16384, 16394, 16896, 66560}
	for _, size := range sizes {
		h := sha256.New()
		t.Logf("Testing file of size: %db, with password: %s", size, password)
		b, err := randBytes(size)
		if err != nil {
			t.Errorf("randBytes(%d) => %q; want nil", size, err)
			continue
		}
		encReader, err := newEncryptReader(bytes.NewReader(b), password, salt, 1024)
		if err != nil {
			t.Errorf("NewEncryptReader() => %q; want nil", err)
			continue
		}
		cipher, err := ioutil.ReadAll(io.TeeReader(encReader, h))
		if err != nil {
			t.Errorf("ioutil.ReadAll(*EncryptReader) => %q; want nil", err)
			continue
		}
		want := h.Sum(nil)
		h.Reset()
		got, err := Hash(bytes.NewReader(b), bytes.NewReader(cipher[0:HeaderSize]), password, h)
		if err != nil {
			t.Errorf("Hash() => err = %q; want nil", err)
			continue
		}
		if !bytes.Equal(got, want) {
			t.Errorf("Hash() => %v; want %v", got, want)
		}
	}

}
