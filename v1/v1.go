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

// Package v1 implements the first version of encryption for drive
// It uses AES-256 in CTR mode for encryption and uses authenticates
// with an HMAC using SHA-512.
//
// This package should always be able to decrypt files that were encrypted
// using this package. If there is a change that needs to be made that would
// prevent decryption of old files, it should be done in a new version.

package v1

import (
	"bufio"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha512"
	"encoding/binary"
	"errors"
	"hash"
	"io"
	"os"

	"github.com/odeke-em/go-utils/tmpfile"
	"golang.org/x/crypto/scrypt"
)

const (
	// The size of the HMAC sum.
	hmacSize = sha512.Size

	// The size of the HMAC key.
	hmacKeySize = 32 // 256 bits

	// The size of the random salt.
	saltSize = 32 // 256 bits

	// The size of the AES key.
	aesKeySize = 32 // 256 bits

	// The size of the AES block.
	blockSize = aes.BlockSize

	// The number of iterations to use in for key generation
	// See N value in https://godoc.org/golang.org/x/crypto/scrypt#Key
	// Must be a power of 2.
	scryptIterations int32 = 262144 // 2^18
)

const _16KB = 16 * 1024

var (
	// The underlying hash function to use for HMAC.
	hashFunc = sha512.New

	// The amount of key material we need.
	keySize = hmacKeySize + aesKeySize

	// The size of the Header.
	HeaderSize = 4 + saltSize + blockSize

	// The overhead added to the file by using this library.
	// Overhead + len(plaintext) == len(ciphertext)
	Overhead = HeaderSize + hmacSize
)

var DecryptErr = errors.New("message corrupt or incorrect password")

// randBytes returns random bytes in a byte slice of size.
func randBytes(size int) ([]byte, error) {
	b := make([]byte, size)
	_, err := rand.Read(b)
	return b, err
}

// keys derives AES and HMAC keys from a password and salt.
func keys(pass, salt []byte, iterations int) (aesKey, hmacKey []byte, err error) {
	key, err := scrypt.Key(pass, salt, iterations, 8, 1, keySize)
	if err != nil {
		return nil, nil, err
	}
	aesKey = append(aesKey, key[:aesKeySize]...)
	hmacKey = append(hmacKey, key[aesKeySize:keySize]...)
	return aesKey, hmacKey, nil
}

// Make sure we implement io.ReadWriter.
var _ io.ReadWriter = &hashReadWriter{}

// hashReadWriter hashes on write and on read finalizes the hash and returns it.
// Writes after a Read will return an error.
type hashReadWriter struct {
	hash hash.Hash
	done bool
	sum  io.Reader
}

// Write implements io.Writer
func (h *hashReadWriter) Write(p []byte) (int, error) {
	if h.done {
		return 0, errors.New("writing to hashReadWriter after read is not allowed")
	}
	return h.hash.Write(p)
}

// Read implements io.Reader.
func (h *hashReadWriter) Read(p []byte) (int, error) {
	if !h.done {
		h.done = true
		h.sum = bytes.NewReader(h.hash.Sum(nil))
	}
	return h.sum.Read(p)
}

// encInt32 will encode a int32 in to a byte slice.
func encInt32(i int32) ([]byte, error) {
	buf := new(bytes.Buffer)
	if err := binary.Write(buf, binary.LittleEndian, i); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// decInt32 will read an int32 from a reader and return the byte slice and the int32.
func decInt32(r io.Reader) (b []byte, i int32, err error) {
	buf := new(bytes.Buffer)
	tr := io.TeeReader(r, buf)
	err = binary.Read(tr, binary.LittleEndian, &i)
	return buf.Bytes(), i, err
}

// NewEncryptReader returns an io.Reader wrapping the provided io.Reader.
// It uses a user provided password and a random salt to derive keys.
// If the key is provided interactively, it should be verified since there
// is no recovery.
func NewEncryptReader(r io.Reader, pass []byte) (io.Reader, error) {
	salt, err := randBytes(saltSize)
	if err != nil {
		return nil, err
	}
	return newEncryptReader(r, pass, salt, scryptIterations)
}

// newEncryptReader returns a encryptReader wrapping an io.Reader.
// It uses a user provided password and the provided salt iterated the
// provided number of times to derive keys.
func newEncryptReader(r io.Reader, pass, salt []byte, iterations int32) (io.Reader, error) {
	itersAsBytes, err := encInt32(iterations)
	if err != nil {
		return nil, err
	}
	aesKey, hmacKey, err := keys(pass, salt, int(iterations))
	if err != nil {
		return nil, err
	}
	iv, err := randBytes(blockSize)
	if err != nil {
		return nil, err
	}
	var header []byte
	header = append(header, itersAsBytes...)
	header = append(header, salt...)
	header = append(header, iv...)
	return encrypter(r, aesKey, hmacKey, iv, header)
}

// encrypter returns the encrypted reader passed on the keys and IV provided.
func encrypter(r io.Reader, aesKey, hmacKey, iv, header []byte) (io.Reader, error) {
	b, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, err
	}
	h := hmac.New(hashFunc, hmacKey)
	hr := &hashReadWriter{hash: h}
	sr := &cipher.StreamReader{R: r, S: cipher.NewCTR(b, iv)}
	return io.MultiReader(io.TeeReader(io.MultiReader(bytes.NewReader(header), sr), hr), hr), nil
}

// decodeHeader decodes the header of the reader.
// It returns the keys, IV, and original header using the password and iterations in the reader.
func decodeHeader(r io.Reader, password []byte) (aesKey, hmacKey, iv, header []byte, err error) {
	itersAsBytes, iterations, err := decInt32(r)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	salt := make([]byte, saltSize)
	iv = make([]byte, blockSize)
	_, err = io.ReadFull(r, salt)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	_, err = io.ReadFull(r, iv)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	aesKey, hmacKey, err = keys(password, salt, int(iterations))
	if err != nil {
		return nil, nil, nil, nil, err
	}
	header = append(header, itersAsBytes...)
	header = append(header, salt...)
	header = append(header, iv...)
	return aesKey, hmacKey, iv, header, err
}

// decryptReader wraps a io.Reader decrypting its content.
type decryptReader struct {
	tmpFile *tmpfile.TmpFile
	sReader *cipher.StreamReader
}

// NewDecryptReader creates an io.ReadCloser wrapping an io.Reader.
// It has to read the entire io.Reader to disk using a temp file so that it can
// hash the contents to verify that it is safe to decrypt.
// If the file is athenticated, the DecryptReader will be returned and
// the resulting bytes will be the plaintext.
func NewDecryptReader(r io.Reader, pass []byte) (d io.ReadCloser, err error) {
	mac := make([]byte, hmacSize)
	aesKey, hmacKey, iv, header, err := decodeHeader(r, pass)
	h := hmac.New(hashFunc, hmacKey)
	h.Write(header)
	if err != nil {
		return nil, err
	}
	dst, err := tmpfile.New(&tmpfile.Context{
		Dir:    os.TempDir(),
		Suffix: "drive-encrypted-",
	})
	if err != nil {
		return nil, err
	}
	// If there is an error, try to delete the temp file.
	defer func() {
		if err != nil {
			dst.Done()
		}
	}()
	b, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, err
	}
	d = &decryptReader{
		tmpFile: dst,
		sReader: &cipher.StreamReader{R: dst, S: cipher.NewCTR(b, iv)},
	}
	w := io.MultiWriter(h, dst)
	buf := bufio.NewReaderSize(r, _16KB)
	for {
		b, err := buf.Peek(_16KB)
		if err != nil && err != io.EOF {
			return nil, err
		}
		if err == io.EOF {
			left := buf.Buffered()
			if left < hmacSize {
				return nil, DecryptErr
			}
			copy(mac, b[left-hmacSize:left])
			_, err = io.CopyN(w, buf, int64(left-hmacSize))
			if err != nil {
				return nil, err
			}
			break
		}
		_, err = io.CopyN(w, buf, _16KB-hmacSize)
		if err != nil {
			return nil, err
		}
	}
	if !hmac.Equal(mac, h.Sum(nil)) {
		return nil, DecryptErr
	}
	dst.Seek(0, 0)
	return d, nil
}

// Read implements io.Reader.
func (d *decryptReader) Read(dst []byte) (int, error) {
	return d.sReader.Read(dst)
}

// Close implements io.Closer.
func (d *decryptReader) Close() error {
	return d.tmpFile.Done()
}

// Hash hashes the plaintext based on the header of the encrypted file and returns the hash Sum.
func Hash(plainTextR io.Reader, headerR io.Reader, password []byte, h hash.Hash) ([]byte, error) {
	aesKey, hmacKey, iv, eHeader, err := decodeHeader(headerR, password)
	if err != nil {
		return nil, err
	}
	encReader, err := encrypter(plainTextR, aesKey, hmacKey, iv, eHeader)
	if err != nil {
		return nil, err
	}
	if _, err := io.Copy(h, encReader); err != nil {
		return nil, err
	}
	return h.Sum(nil), nil
}
