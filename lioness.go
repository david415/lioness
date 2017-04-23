// lioness.go - A LIONESS-BLAKE2b-ChaCha20 implementation.
//
// To the extent possible under law, Yawning Angel has waived all copyright
// and related or neighboring rights to lioness, using the Creative
// Commons "CC0" public domain dedication. See LICENSE or
// <http://creativecommons.org/publicdomain/zero/1.0/> for full details.

package lioness

import (
	"errors"

	"git.schwanenlied.me/yawning/chacha20.git"
	"github.com/minio/blake2b-simd"
)

const (
	// KeySize is the key size in bytes.
	KeySize = 128

	// IVSize is the initialization vector size in bytes.
	IVSize = 48

	// MinBlockSize is the minimum block size in bytes.
	MinBlockSize = 32 + 1

	// MaxBlockSize is the maximum block size in bytes.
	MaxBlockSize = 32 + (1 << 36)

	lSize = chacha20.KeySize
)

var (
	// ErrBlockSize is the error returned when the block size is invalid.
	ErrBlockSize = errors.New("lioness: invalid block size")

	xorBytes32 = xorBytes32Ref
)

// Encrypt encrypts a block.  dst and src may overlap.
func Encrypt(key [KeySize]byte, iv [IVSize]byte, dst, src []byte) error {
	// XXX: In theory I should enforce MaxBlockSize, but it's > sizeof(int)
	// on 32 bit systems.
	if len(src) < MinBlockSize || len(dst) < len(src) {
		return ErrBlockSize
	}

	rSize := len(dst) - lSize
	l := make([]byte, lSize)
	r := make([]byte, rSize)
	var tmp [lSize + IVSize/4]byte
	defer zeroBytes(tmp[:])

	k1 := key[0:32]
	k2 := key[32:64]
	k3 := key[64:96]
	k4 := key[96:128]
	iv1 := iv[0:12]
	iv2 := iv[12:24]
	iv3 := iv[24:36]
	iv4 := iv[36:48]

	var s chacha20.Cipher
	defer s.Reset()

	var hCfg blake2b.Config
	hCfg.Size = lSize
	hCfg.Key = tmp[:]

	// R = ChaCha20(L ^ k1, iv1, R)
	xorBytes32(tmp[:lSize], src[0:lSize], k1)
	if err := s.ReKey(tmp[:lSize], iv1); err != nil {
		return err
	}
	s.XORKeyStream(r, src[lSize:])

	// L = L ^ BLAKE2b(k2 | iv2, R)
	copy(tmp[:lSize], k2)
	copy(tmp[lSize:], iv2)
	h, err := blake2b.New(&hCfg)
	if err != nil {
		return err
	}
	defer h.Reset()
	h.Write(r)
	htmp := h.Sum(nil)
	xorBytes32(l, src[0:lSize], htmp)
	htmp = htmp[:0]

	// R = ChaCha20(L ^ k3, iv3, R)
	xorBytes32(tmp[:lSize], l, k3)
	if err := s.ReKey(tmp[:lSize], iv3); err != nil {
		return err
	}
	s.XORKeyStream(r, r)

	// L ^ BLAKE2b(k4 | iv4, R)
	copy(tmp[:lSize], k4)
	copy(tmp[lSize:], iv4)
	hh, err := blake2b.New(&hCfg) // I wish blake2b-simd supported rekeying.
	if err != nil {
		return err
	}
	defer hh.Reset()
	hh.Write(r)
	htmp = hh.Sum(htmp)
	defer zeroBytes(htmp)
	xorBytes32(l, l, htmp)

	copy(dst, l)
	copy(dst[lSize:], r)

	return nil
}

// Decrypt decrypts a block.  dst and src may overlap.
func Decrypt(key [KeySize]byte, iv [IVSize]byte, dst, src []byte) error {
	// XXX: In theory I should enforce MaxBlockSize, but it's > sizeof(int)
	// on 32 bit systems.
	if len(src) < MinBlockSize || len(dst) < len(src) {
		return ErrBlockSize
	}

	k1 := key[0:32]
	k2 := key[32:64]
	k3 := key[64:96]
	k4 := key[96:128]
	iv1 := iv[0:12]
	iv2 := iv[12:24]
	iv3 := iv[24:36]
	iv4 := iv[36:48]

	rSize := len(dst) - lSize
	l := make([]byte, lSize)
	r := make([]byte, rSize)
	var tmp [lSize + IVSize/4]byte
	defer zeroBytes(tmp[:])

	var s chacha20.Cipher
	defer s.Reset()

	var hCfg blake2b.Config
	hCfg.Size = lSize
	hCfg.Key = tmp[:]

	// L = L ^ BLAKE2b(k4 | iv4, R)
	copy(tmp[:lSize], k4)
	copy(tmp[lSize:], iv4)
	h, err := blake2b.New(&hCfg)
	if err != nil {
		return err
	}
	defer h.Reset()
	h.Write(src[lSize:])
	htmp := h.Sum(nil)
	xorBytes32(l, src[0:lSize], htmp)
	htmp = htmp[:0]

	// R = ChaCha20(L ^ k3, iv3, R)
	xorBytes32(tmp[:lSize], l, k3)
	if err := s.ReKey(tmp[:lSize], iv3); err != nil {
		return err
	}
	s.XORKeyStream(r, src[lSize:])

	// L = L ^ BLAKE2b(k2 | iv2, R)
	copy(tmp[:lSize], k2)
	copy(tmp[lSize:], iv2)
	hh, err := blake2b.New(&hCfg) // I wish blake2b-simd supported rekeying.
	if err != nil {
		return err
	}
	defer hh.Reset()
	hh.Write(r)
	htmp = hh.Sum(htmp)
	defer zeroBytes(htmp)
	xorBytes32(l, l, htmp)

	// R = ChaCha20(L ^ k1, iv1, R)
	xorBytes32(tmp[:lSize], l, k1)
	if err := s.ReKey(tmp[:lSize], iv1); err != nil {
		return err
	}
	s.XORKeyStream(r, r)

	copy(dst, l)
	copy(dst[lSize:], r)

	return nil
}

func xorBytes32Ref(dst, a, b []byte) {
	// Note: Before you freak the fuck out and try to optimize this,
	// for more platforms, take note that it's 32 bytes.  Performance
	// here is only meaningful for extremely small messages.

	if len(dst) != 32 {
		panic("lioness: xorBytes32Ref() len != 32")
	}
	for i, v := range a {
		dst[i] = v ^ b[i]
	}
}

func zeroBytes(a []byte) {
	for i := range a {
		a[i] = 0
	}
}
