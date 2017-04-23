// xorbytes_amd64.go - AMD64 optimized xorBytes32.
//
// To the extent possible under law, Yawning Angel has waived all copyright
// and related or neighboring rights to lioness, using the Creative
// Commons "CC0" public domain dedication. See LICENSE or
// <http://creativecommons.org/publicdomain/zero/1.0/> for full details.

// +build amd64,!gccgo,!appengine

package lioness

//go:noescape
func xorBytes32Amd64SSE2(dest, a, b *byte)

func xorBytes32Amd64(dst, a, b []byte) {
	// This is basically a pointless microoptimization, and only
	// helps the 33 byte by 0.8 MB/s on my craptop.  Using AVX2
	// is essentially totally pointless, so I didn't do it.

	if len(dst) != 32 {
		panic("lioness: xorBytes32Amd64() len != 32")
	}

	xorBytes32Amd64SSE2(&dst[0], &a[0], &b[0])
}

func init() {
	xorBytes32 = xorBytes32Amd64
}
