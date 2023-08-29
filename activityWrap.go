package txhelper

// #cgo CFLAGS: -g -Wall
// #cgo LDFLAGS: -lcrypto
// #include <stdlib.h>
// #include <stdint.h>
// #include <openssl/bn.h>
import "C"
import (
	"bytes"
	"fmt"
)

// We use OpenSSL/BN, hence this only tests the cgo code.
func privateCtestWrap() bool {
	ctx := NewContext(100, 1, 5, 1, 32, 3, 2, 3, 1, false)
	a := make([]byte, 33)
	b := make([]byte, 33)
	expectedC := make([]byte, 33)
	expectedC[32] = 4

	a[32] = 8
	b[32] = 2
	c := ctx.ModDiv(a, b)

	if !bytes.Equal(c, expectedC) {
		fmt.Println("point 1")
		return false
	}

	a[32] = 4
	a[31] = 1
	b[32] = 4
	expectedC[32] = 65
	c = ctx.ModDiv(a, b)

	if !bytes.Equal(c, expectedC) {
		fmt.Println("point 2")
		return false
	}

	a[32] = 4
	a[31] = 0
	b[32] = 4
	expectedC[32] = 16
	c = ctx.ModMul(a, b)

	if !bytes.Equal(c, expectedC) {
		fmt.Println("point 3")
		return false
	}

	a[32] = 16
	a[31] = 0
	b[32] = 16
	expectedC[32] = 0
	expectedC[31] = 1
	c = ctx.ModMul(a, b)

	if !bytes.Equal(c, expectedC) {
		return false
	}

	return true
}
