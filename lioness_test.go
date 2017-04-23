// lioness.go - A LIONESS-BLAKE2b-ChaCha20 implementation.
//
// To the extent possible under law, Yawning Angel has waived all copyright
// and related or neighboring rights to lioness, using the Creative
// Commons "CC0" public domain dedication. See LICENSE or
// <http://creativecommons.org/publicdomain/zero/1.0/> for full details.

package lioness

import (
	"bytes"
	"crypto/rand"
	"testing"
)

func TestLionessBasic(t *testing.T) {
	var key [KeySize]byte
	var iv [IVSize]byte
	var src, dst, tmp [1024]byte

	if _, err := rand.Read(key[:]); err != nil {
		t.Error(err)
		t.Fail()
	}
	if _, err := rand.Read(iv[:]); err != nil {
		t.Error(err)
		t.Fail()
	}

	if _, err := rand.Read(src[:]); err != nil {
		t.Error(err)
		t.Fail()
	}

	if err := Encrypt(key, iv, dst[:], src[:]); err != nil {
		t.Error(err)
		t.Fail()
	}

	if bytes.Equal(src[:], dst[:]) {
		t.Error("src/dest match")
		t.Fail()
	}

	if err := Decrypt(key, iv, tmp[:], dst[:]); err != nil {
		t.Error(err)
		t.Fail()
	}

	if !bytes.Equal(src[:], tmp[:]) {
		t.Error("src/tmp mismatch")
		t.Fail()
	}

	// TODO: Test that each subnonce actually changes things.

	// TODO: Test that each subkey actually changes things.
}

var benchOutput []byte

func doBenchEncrypt(b *testing.B, n int) {
	var key [KeySize]byte
	var iv [IVSize]byte
	if _, err := rand.Read(key[:]); err != nil {
		b.Error(err)
		b.Fail()
	}
	if _, err := rand.Read(iv[:]); err != nil {
		b.Error(err)
		b.Fail()
	}

	src := make([]byte, n)
	dst := make([]byte, n)

	b.SetBytes(int64(n))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := Encrypt(key, iv, dst, src); err != nil {
			b.Error(err)
			b.Fatal()
		}
	}

	benchOutput = dst
}

func BenchmarkLionessEncrypt_33(b *testing.B) {
	doBenchEncrypt(b, 33)
}

func BenchmarkLionessEncrypt_512(b *testing.B) {
	doBenchEncrypt(b, 512)
}

func BenchmarkLionessEncrypt_1024(b *testing.B) {
	doBenchEncrypt(b, 1024)
}

func BenchmarkLionessEncrypt_4096(b *testing.B) {
	doBenchEncrypt(b, 4096)
}

func BenchmarkLionessEncrypt_16384(b *testing.B) {
	doBenchEncrypt(b, 16384)
}

func BenchmarkLionessEncrypt_32768(b *testing.B) {
	doBenchEncrypt(b, 32768)
}

func BenchmarkLionessEncrypt_65536(b *testing.B) {
	doBenchEncrypt(b, 65536)
}

func BenchmarkLionessEncrypt_1024768(b *testing.B) {
	doBenchEncrypt(b, 1024768)
}
