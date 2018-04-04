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
	"encoding/hex"
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

var draftTestVectors = []struct {
	key   string
	iv    string
	block string
	want  string
}{
	{
		key:   "1338761c4cbeb912ba90c276b60a6be1f8d1faf88d982c2650c6e3e50a466d33f8adeaf0f7348e97994549695f4c5ebd60cd9bbfb6a1145afd95c0e521aff2572c534ed4d4956149cf349e9b19b9b4a2218aa85f0bc9ff5cef96152c664b9bead6439688565b4032db6132e8d01e3de3d75ac61415fd91fe65ad0b5aee79dd15",
		iv:    "86453b143014e6c2cae0ea111917570d56a030e9ddb3d66e540980b281a22e13ea3c3595bc9492fa5756b0a4ba8dda5f",
		block: "5a66aec61d86899aa42e1785e3d71278cd62a8f0fa3d03023e56efcbeb6edc2b79",
		want:  "6e46fd5a8891e196b311ffedbca854cde93c15c9b7d0eda9a1660161faf0da78a0",
	},
	{
		key:   "a5d7bd43320df4f560a3ff85b05f22dfc3d4e7405d53802305be474de7bf1c33d29da3ab7af680cc8ffb0a58111434004c807fea8af67ae01486f0a2be89463f365b910000c7cd87f80a0e8df7e61f083fbe9cd537f6fc33e7c97062351aa3599b767c6fa8a8fb60dac72573e169b34b2dc73a3edfb0cdad47657a83ea559140",
		iv:    "2ca1a11bff1713d7d6dbaadf1037d53d6a96092fbf74198371e77bf8c77b346b625cc938c449fdb3a11f1851703a1534",
		block: "3e2e5cab574e9baeb9fb9a6c9c1d629b3876577d677cde37e957538ff76f6fae97f72aa40d4039ba32c9957fa1728cee12e0ad322f25021cd409c816d3a1861d804adb25966d6409f6b3a73ecf6b9f85dbe5411697e98b5d34eef2e9c957f54296988fa4374284dc17c85f27e50b73a333bd55f5220d89e9b513395ff8962d2871cdda248e5d8ff019be8c4ef794f9361fe7623385ff3f17088f8edab0b10b1e298d6da11b743b09dc6593821fa780cd0ac9b187dfc33fbf5f9f566efd23a1c7f602a0e2d16a9bb2973a184640cabbe2726ec13ea9eefdf563cff7cc3827ad6a0cf0040db7180909c5f940a85333880ad957b651d210c86568ce8dc12687ec87b60c4aec2e1a37cc12904f568e14d30e67de4aaf6b70678d3dd609434f2aae6d762c2f04e00a32fe06f1ec2860c7b7abc780137330157a381bc6655d4bf17ed1f4031e052105efe74bb6c1d5215b225dd7388841d9f72df9ce5ca64eba668ae4ac17d5b3c8a7d216cd58c242f4c8ffdb02961fa3880fb616fd7939af01c100457dffc010072c2bf00610257a31ffb9bbf569e1a6604691c5a727ff133fd4fbc0067a012a9bc34f6bd2b6544c126853ada937cdf4b426a603ec4a7c13e06b48752c4fce5d632ca0b4ece880a870976b009956bbfaf4f29b4b22e763c94200db5906d0ab67c221e219e06dd8bffe617112f5f5703a",
		want:  "484716632eda1a807a7cc84b4b7824ae968c687cdc2bbe982012a718d924db4b9b33e78374990e2a2cd7f8d46fbedad701960e6db1c7198ae261f3fc6ad23d845df73b2d0e8a8f5f6305a0ea0867d7d16b3a0fff662536090ff5580b3020351c7c004c3f5ca126a03fa46646c460fd50d52f7748c45882bd995a6bc066930df1ec23e247e5cc58a2cfe4224224a784f6e408ec47cffe4a09473526e679e6527ff6144fc7b0ea9559ad8ce474b71b73c3585fb53327dc698e87d9755b452bdb9f8c19791de68101edd492c9a8b10227aae8d39214bb222cae95cd352e06ab67e753d56b5f07c958aef105423e27a4eac8a7e956e90f731d255a5ac3fd41fcef167ffc2f080d42a9bb008a7f32a16b7a787b44bb683729ff8dc2244755d7b124f80c6b9dc9a98fb3ae238ad1a25960beb952aa27a73e85bc0c0ab421b2f4ae6e2829db6103e9f3a8399a1e27f0fcebdc30cd76560fce1b88447ac18a362a3ff3a3bf4b8361fcac8eede3eeeb30472c3cd4d29ebc8d194143d9554362da27387fde22248c7e2d91010a816a368bcc221f5adf17dc004eaedf997a08bbab85cca1cfa42e132dd411a6fe38efe132a0ef5b1ca9ce94d48b2a0b52b10a90101f8dd70e94a887cf2de58af36f759464fa7b771b7a8c803116d1091329824f03829d0a21c5b5a27f5a1d9cb48d3dace7eead9331fc89abaf",
	},
}

func TestLionessVectors(t *testing.T) {
	for i, v := range draftTestVectors {
		block, err := hex.DecodeString(v.block)
		if err != nil {
			t.Error(err)
			t.Fail()
		}
		key, err := hex.DecodeString(v.key)
		if err != nil {
			t.Error(err)
			t.Fail()
		}
		iv, err := hex.DecodeString(v.iv)
		if err != nil {
			t.Error(err)
			t.Fail()
		}
		var keyArray [KeySize]byte
		copy(keyArray[:], key)
		var ivArray [IVSize]byte
		copy(ivArray[:], iv)
		ciphertext := make([]byte, len(block))
		err = Encrypt(keyArray, ivArray, ciphertext, block)
		if err != nil {
			t.Errorf("[%d]: encryption failed: %s", i, err)
			t.Fail()
		}
		want, err := hex.DecodeString(v.want)
		if err != nil {
			t.Error(err)
			t.Fail()
		}
		if !bytes.Equal(ciphertext[:], want) {
			t.Errorf("ciphertext mismatch for test vector %d", i)
			t.Fail()
		}
	}
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
