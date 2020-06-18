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

// Package dcrypto provides end to end encryption for drive.

package dcrypto

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"hash"
	"io"

	"github.com/textileio/dcrypto/v1"
)

// Version is the version of the en/decryption library used.
type Version uint32

// decrypter is a function that creates a decrypter.
type decrypter func(io.Reader, []byte) (io.ReadCloser, error)

// encrypter is a function that creates a encrypter.
type encrypter func(io.Reader, []byte) (io.Reader, error)

// hasher is a function that returns the hash of a plaintext as if it were encrypted.
type hasher func(io.Reader, io.Reader, []byte, hash.Hash) ([]byte, error)

// These are the different versions of the en/decryption library.
const (
	V1 Version = iota
)

// PreferedVersion is the preferred version of encryption.
const PreferedVersion = V1

var encrypters map[Version]encrypter
var decrypters map[Version]decrypter
var hashers map[Version]hasher

// MaxHeaderSize is the maximum header size of all versions.
// This many bytes at the beginning of a file should be enough to compute
// a hash of a local file.
var MaxHeaderSize = v1.HeaderSize + 4

// Overhead is the overhead added by the preferred encryption library plus the version.
var Overhead = v1.Overhead + 4

func init() {
	decrypters = map[Version]decrypter{
		V1: v1.NewDecryptReader,
	}

	encrypters = map[Version]encrypter{
		V1: v1.NewEncryptReader,
	}
	hashers = map[Version]hasher{
		V1: v1.Hash,
	}
}

// NewEncrypter returns an encrypting reader using the PreferedVersion.
func NewEncrypter(r io.Reader, password []byte) (io.Reader, error) {
	v, err := writeVersion(PreferedVersion)
	if err != nil {
		return nil, err
	}
	encrypterFn, ok := encrypters[PreferedVersion]
	if !ok {
		return nil, fmt.Errorf("%v version could not be found", PreferedVersion)
	}
	encReader, err := encrypterFn(r, password)
	if err != nil {
		return nil, err
	}
	return io.MultiReader(bytes.NewReader(v), encReader), nil
}

// NewDecrypter returns a decrypting reader based on the version used to encrypt.
func NewDecrypter(r io.Reader, password []byte) (io.ReadCloser, error) {
	version, err := readVersion(r)
	if err != nil {
		return nil, err
	}
	decrypterFn, ok := decrypters[version]
	if !ok {
		return nil, fmt.Errorf("unknown decrypter for version(%d)", version)
	}
	return decrypterFn(r, password)
}

// Hash will hash of plaintext based on the header of the encrypted file and returns the hash Sum.
func Hash(r io.Reader, header io.Reader, password []byte, hashFunc func() hash.Hash) ([]byte, error) {
	h := hashFunc()
	version, err := readVersion(io.TeeReader(header, h))
	if err != nil {
		return nil, err
	}
	hasherFn, ok := hashers[version]
	if !ok {
		return nil, fmt.Errorf("unknown hasher for version(%d)", version)
	}
	return hasherFn(r, header, password, h)
}

// writeVersion converts a Version to a []byte.
func writeVersion(i Version) ([]byte, error) {
	buf := new(bytes.Buffer)
	if err := binary.Write(buf, binary.LittleEndian, i); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// readVersion reads and returns a Version from reader.
func readVersion(r io.Reader) (v Version, err error) {
	err = binary.Read(r, binary.LittleEndian, &v)
	return v, err
}
