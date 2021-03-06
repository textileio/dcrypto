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

package dcrypto_test

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"io"
	"io/ioutil"
	"testing"

	"github.com/textileio/dcrypto"
)

// randBytes returns random bytes in a byte slice of size.
func randBytes(size int) ([]byte, error) {
	b := make([]byte, size)
	_, err := rand.Read(b)
	return b, err
}

// TestNewKey just tests that NewKey doesn't error.
func TestNewKey(t *testing.T) {
	key, err := dcrypto.NewKey()
	if err != nil {
		t.Fatalf("NewKey() => %q", err)
	}
	if len(key) != 64 {
		t.Fatalf("expected key length 64, got %d", len(key))
	}
}

// TestRoundTrip tests several size sets of data going through the encrypt/decrypt
// to make sure they come out the same.
func TestRoundTrip(t *testing.T) {
	sizes := []int{0, 24, 1337, 66560}
	keys := make([][]byte, 100)
	for i := range keys {
		rk, err := randBytes(64)
		if err != nil {
			t.Fatalf("randBytes() => %q", err)
		}
		keys[i] = rk
	}
	for _, key := range keys {
		for _, size := range sizes {
			t.Logf("Testing file of size: %db", size)
			b, err := randBytes(size)
			if err != nil {
				t.Errorf("randBytes(%d) => %q; want nil", size, err)
				continue
			}
			encReader, err := dcrypto.NewEncrypter(bytes.NewReader(b), key)
			if err != nil {
				t.Errorf("NewEncrypter() => %q; want nil", err)
				continue
			}
			cipher, err := ioutil.ReadAll(encReader)
			if err != nil {
				t.Errorf("ioutil.ReadAll(*Encrypter) => %q; want nil", err)
				continue
			}
			decReader, err := dcrypto.NewDecrypter(bytes.NewReader(cipher), key)
			if err != nil {
				t.Errorf("NewDecrypter() => %q; want nil", err)
				continue
			}
			plain, err := ioutil.ReadAll(decReader)
			_ = decReader.Close()
			if err != nil {
				t.Errorf("ioutil.ReadAll(*Decrypter) => %q; want nil", err)
				continue
			}
			if !bytes.Equal(b, plain) {
				t.Errorf("Encrypt/Decrypt of file size %d, resulted in different values", size)
			}
		}
	}
}

// TestRoundTripWithPassword tests several size sets of data going through the encrypt/decrypt
// to make sure they come out the same.
func TestRoundTripWithPassword(t *testing.T) {
	sizes := []int{0, 24, 1337, 66560}
	spasswords := []string{
		"",
		"guest",
	}
	for _, x := range []int{13, 400} {
		rp, err := randBytes(x)
		if err != nil {
			t.Fatalf("randBytes() => %q", err)
		}
		spasswords = append(spasswords, string(rp))
	}
	for _, spass := range spasswords {
		password := []byte(spass)
		for _, size := range sizes {
			t.Logf("Testing file of size: %db", size)
			b, err := randBytes(size)
			if err != nil {
				t.Errorf("randBytes(%d) => %q; want nil", size, err)
				continue
			}
			encReader, err := dcrypto.NewEncrypterWithPassword(bytes.NewReader(b), password)
			if err != nil {
				t.Errorf("NewEncrypterWithPassword() => %q; want nil", err)
				continue
			}
			cipher, err := ioutil.ReadAll(encReader)
			if err != nil {
				t.Errorf("ioutil.ReadAll(*Encrypter) => %q; want nil", err)
				continue
			}
			decReader, err := dcrypto.NewDecrypterWithPassword(bytes.NewReader(cipher), password)
			if err != nil {
				t.Errorf("NewDecrypterWithPassword() => %q; want nil", err)
				continue
			}
			plain, err := ioutil.ReadAll(decReader)
			_ = decReader.Close()
			if err != nil {
				t.Errorf("ioutil.ReadAll(*Decrypter) => %q; want nil", err)
				continue
			}
			if !bytes.Equal(b, plain) {
				t.Errorf("Encrypt/Decrypt of file size %d, resulted in different values", size)
			}
		}
	}
}

func TestHash(t *testing.T) {
	key, err := randBytes(64)
	if err != nil {
		t.Fatalf("randBytes() => %q", err)
	}
	sizes := []int{0, 24, 1337, 66560}
	for _, size := range sizes {
		h := sha256.New()
		t.Logf("Testing file of size: %db", size)
		b, err := randBytes(size)
		if err != nil {
			t.Errorf("randBytes(%d) => %q; want nil", size, err)
			continue
		}
		encReader, err := dcrypto.NewEncrypter(bytes.NewReader(b), key)
		if err != nil {
			t.Errorf("NewEncryper() => %q; want nil", err)
			continue
		}
		cipher, err := ioutil.ReadAll(io.TeeReader(encReader, h))
		if err != nil {
			t.Errorf("ioutil.ReadAll(*EncryptReader) => %q; want nil", err)
			continue
		}
		want := h.Sum(nil)
		got, err := dcrypto.Hash(bytes.NewReader(b), bytes.NewReader(cipher[0:dcrypto.MaxHeaderSize]), key, sha256.New)
		if err != nil {
			t.Errorf("Hash() => err = %q; want nil", err)
			continue
		}
		if !bytes.Equal(got, want) {
			t.Errorf("Hash() => %v; want %v", got, want)
		}
	}
}

func TestHashWithPassword(t *testing.T) {
	password := []byte("test")
	sizes := []int{0, 24, 1337, 66560}
	for _, size := range sizes {
		h := sha256.New()
		t.Logf("Testing file of size: %db, with password: %s", size, password)
		b, err := randBytes(size)
		if err != nil {
			t.Errorf("randBytes(%d) => %q; want nil", size, err)
			continue
		}
		encReader, err := dcrypto.NewEncrypterWithPassword(bytes.NewReader(b), password)
		if err != nil {
			t.Errorf("NewEncryperWithPassword() => %q; want nil", err)
			continue
		}
		cipher, err := ioutil.ReadAll(io.TeeReader(encReader, h))
		if err != nil {
			t.Errorf("ioutil.ReadAll(*EncryptReader) => %q; want nil", err)
			continue
		}
		want := h.Sum(nil)
		got, err := dcrypto.HashWithPassword(bytes.NewReader(b), bytes.NewReader(cipher[0:dcrypto.MaxHeaderSize]), password, sha256.New)
		if err != nil {
			t.Errorf("HashWithPassword() => err = %q; want nil", err)
			continue
		}
		if !bytes.Equal(got, want) {
			t.Errorf("HashWithPassword() => %v; want %v", got, want)
		}
	}
}
