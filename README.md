# lioness - LIONESS-BLAKE2b-ChaCha20
#### Yawning Angel (yawning at schwanenlied dot me)

Yet another Go LIONESS implementation, similar to go-lioness, though with
slightly different parameterization, and support for a tweak.  The
implementations are NOT interoperable.

H() is BLAKE2b with a 256 bit key, 96 bit tweak.
S() is ChaCha20 with a 256 bit key, 96 bit tweak.
