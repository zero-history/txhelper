package txhelper

import (
	"database/sql"
	"go.dedis.ch/kyber/v3/group/edwards25519"
	"go.dedis.ch/kyber/v3/util/key"
	"go.dedis.ch/kyber/v3/xof/blake2xb"
	"log"
	"unsafe"
)

// #cgo CFLAGS: -g -Wall
// #cgo LDFLAGS: -lcrypto
// #include <stdlib.h>
// #include <stdint.h>
// #include <openssl/bn.h>
import "C"

type ExeContext struct {
	exeId            int // will be used for databases
	uType            int // 1 - client, 0 - peer
	txModel          int // transaction model
	sigContext       *SignatureContext
	payloadSize      uint16 // data size per output (bytes)
	averageInputMax  uint8  // average number of inputs will be in [0, averageInputMax]
	averageOutputMax uint8  // average number of outputs  will be in [0, averageOutputMax]
	distributionType int    // output Data size distribution

	totalUsers int // total number of users represented if this is a client
	totalTx    int // total number of transactions if this is a peer
	totalBlock int // total number of blocks  if this is a peer

	inputPointer   int // inputs are chosen from round-robin method
	outputPointer  int // inputs are chosen from round-robin method
	currentUsers   int
	currentOutputs int // in Origami, currentUsers = currentOutputs
	deletedOutputs int //
	groupContext   key.Suite

	bnQ   *C.BIGNUM
	bnCtx *C.BN_CTX
	bnOne []byte

	db *sql.DB // sqlite database
}

func NewContext(exeId int, uType int, txType int, sigType int32, averageSize uint16, totalUsers int,
	averageInputMax uint8, averageOutputMax uint8, distributionType int) ExeContext {
	log.SetFlags(log.LstdFlags | log.Lshortfile)

	ctx := ExeContext{
		exeId:            exeId,
		uType:            uType,
		txModel:          txType,
		payloadSize:      averageSize,
		averageInputMax:  averageInputMax,
		averageOutputMax: averageOutputMax,
		distributionType: distributionType,
		totalUsers:       totalUsers,
		totalBlock:       0,
		totalTx:          0,
		inputPointer:     0,
		outputPointer:    0,
		currentUsers:     0,
		currentOutputs:   0,
		deletedOutputs:   0,
	}

	// generate group context
	rng := blake2xb.New(nil)
	ctx.groupContext = edwards25519.NewBlakeSHA256Ed25519WithRand(rng)

	// generate signature context
	ctx.sigContext = NewSigContext(sigType)
	ctx.sigContext.SigType = sigType

	if averageInputMax > averageOutputMax {
		log.Fatal("can't be averageInputMax > averageOutputMax")
	}

	if int(averageInputMax) >= totalUsers {
		log.Fatal("can't be averageInputMax >= totalUsers")
	}

	// generate all users for clients
	if uType == 1 {
		if ctx.txModel == 1 || ctx.txModel == 3 || ctx.txModel == 5 {
			ctx.initClientDB()
		} else if ctx.txModel == 2 || ctx.txModel == 4 || ctx.txModel == 6 {
			ctx.initClientDB()
		}
	} else if ctx.uType == 2 {
		ctx.initPeerDB()
	} else {
		log.Fatal("unknown utype")
	}

	if ctx.txModel == 5 || ctx.txModel == 6 {
		// 11299664372728897582526563392681553682012299567391845763352611480686339092302161
		qBytes := []byte{13, 4, 90, 151, 95, 128, 247, 206, 252, 192, 83, 31, 233, 88, 11, 186, 251, 63, 158, 54, 191, 232, 0, 72, 241, 158, 134, 107, 133, 75, 78, 157, 223}
		ctx.bnQ = C.BN_new()
		ctx.bnCtx = C.BN_CTX_new()
		C.BN_bin2bn((*C.uchar)(unsafe.Pointer(&qBytes[0])), 33, ctx.bnQ)
		ctx.bnOne = make([]byte, 33)
		ctx.bnOne[33-1] = 1
	}

	return ctx
}
