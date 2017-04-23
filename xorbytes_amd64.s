// xorbytes_amd64.s - AMD64 SSE2 32 byte XOR.
//
// To the extent possible under law, Yawning Angel has waived all copyright
// and related or neighboring rights to lioness, using the Creative
// Commons "CC0" public domain dedication. See LICENSE or
// <http://creativecommons.org/publicdomain/zero/1.0/> for full details.

TEXT ·xorBytes32Amd64SSE2(SB),4,$0-24
	MOVQ dst+0(FP), AX
	MOVQ a+8(FP), BX
	MOVQ b+16(FP), CX
	MOVOU 0(BX), X0
	MOVOU 0(CX), X1
	MOVOU 16(BX), X2
	MOVOU 16(CX), X3
	PXOR X1, X0
	PXOR X3, X2
	MOVOU X0, 0(AX)
	MOVOU X2, 16(AX)
	RET
