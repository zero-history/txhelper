/**********************************************************************
 * Copyright (c) 2017 Jayamine Alupotha                               *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/

package txhelper

import "unsafe"

// #cgo CFLAGS: -g -Wall
// #cgo LDFLAGS: -lcrypto
// #include <stdlib.h>
// #include <stdint.h>
// #include <openssl/bn.h>
import "C"

// computeAppActivity returns activity = \prod hash(out.pk, out.n, out.data) x (\prod hash(in.pk, in.n, in.data))^{-1}
func (ctx *ExeContext) computeAppActivity(data *AppData) (activityProof []byte) {
	temp := C.BN_new()
	d := C.BN_new()
	C.BN_bin2bn((*C.uchar)(unsafe.Pointer(&ctx.bnOne[0])), 33, temp)
	C.BN_copy(d, temp)

	printer := make([]byte, 33)
	C.BN_bn2binpad(d, (*C.uchar)(unsafe.Pointer(&printer[0])), 33)

	for i := 0; i < len(data.Inputs); i++ {
		C.BN_bin2bn((*C.uchar)(unsafe.Pointer(&data.Inputs[i].Header[0])), 32, temp)
		C.BN_mod_mul(d, d, temp, ctx.bnQ, ctx.bnCtx)
	}
	C.BN_mod_inverse(d, d, ctx.bnQ, ctx.bnCtx)

	for i := 0; i < len(data.Outputs); i++ {
		C.BN_bin2bn((*C.uchar)(unsafe.Pointer(&data.Outputs[i].header[0])), 32, temp)
		C.BN_mod_mul(d, d, temp, ctx.bnQ, ctx.bnCtx)
	}
	activityProof = make([]byte, 33)
	C.BN_bn2binpad(d, (*C.uchar)(unsafe.Pointer(&activityProof[0])), 33)
	C.BN_clear_free(temp)
	C.BN_clear_free(d)
	return activityProof
}

// ModMul h0 = (h0 * h1) % q
func (ctx *ExeContext) ModMul(a []byte, b []byte) (c []byte) {
	c = make([]byte, 33)
	h0 := C.BN_new()
	h1 := C.BN_new()
	C.BN_bin2bn((*C.uchar)(unsafe.Pointer(&a[0])), 33, h0)
	C.BN_bin2bn((*C.uchar)(unsafe.Pointer(&b[0])), 33, h1)
	C.BN_mod_mul(h0, h0, h1, ctx.bnQ, ctx.bnCtx)
	C.BN_bn2binpad(h0, (*C.uchar)(unsafe.Pointer(&c[0])), 33)
	C.BN_clear_free(h0)
	C.BN_clear_free(h1)

	return c
}

// ModDiv h0 = (h0 * h1^{-1}) % q
func (ctx *ExeContext) ModDiv(a []byte, b []byte) (c []byte) {
	c = make([]byte, 33)
	h0 := C.BN_new()
	h1 := C.BN_new()
	C.BN_bin2bn((*C.uchar)(unsafe.Pointer(&a[0])), 33, h0)
	C.BN_bin2bn((*C.uchar)(unsafe.Pointer(&b[0])), 33, h1)
	C.BN_mod_inverse(h1, h1, ctx.bnQ, ctx.bnCtx)
	C.BN_mod_mul(h0, h0, h1, ctx.bnQ, ctx.bnCtx)
	C.BN_bn2binpad(h0, (*C.uchar)(unsafe.Pointer(&c[0])), 33)
	C.BN_clear_free(h0)
	C.BN_clear_free(h1)

	return c
}

// slefModMul h0 = (h0 * h1) % q
func (ctx *ExeContext) selfModMul(h0 *C.BIGNUM, b []byte) {
	h1 := C.BN_new()
	C.BN_bin2bn((*C.uchar)(unsafe.Pointer(&b[0])), 33, h1)
	C.BN_mod_mul(h0, h0, h1, ctx.bnQ, ctx.bnCtx)
	C.BN_clear_free(h1)
}

// selfModDiv h0 = (h0 * h1^{-1}) % q
func (ctx *ExeContext) selfModDiv(h0 *C.BIGNUM, b []byte) {
	h1 := C.BN_new()
	C.BN_bin2bn((*C.uchar)(unsafe.Pointer(&b[0])), 33, h1)
	C.BN_mod_inverse(h1, h1, ctx.bnQ, ctx.bnCtx)
	C.BN_mod_mul(h0, h0, h1, ctx.bnQ, ctx.bnCtx)
	C.BN_clear_free(h1)
}
