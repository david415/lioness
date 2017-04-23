# lioness - LIONESS-BLAKE2b-ChaCha20
#### Yawning Angel (yawning at schwanenlied dot me)

Yet another Go LIONESS implementation, similar to go-lioness, though with
slightly different parameterization, and support for a tweak.  The
implementations are NOT interoperable.

Notes:

 * H() is BLAKE2b with a 256 bit key, 96 bit tweak.
 * S() is ChaCha20 with a 256 bit key, 96 bit tweak.
 * The crypto implementations used have assembly for AMD64.
 * It's still kind of slow, because it's LIONESS, and it's written in Go.
