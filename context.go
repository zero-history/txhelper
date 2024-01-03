/**********************************************************************
 * Copyright (c) 2017 Jayamine Alupotha                               *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/

package txhelper

import (
	"crypto/sha256"
	"database/sql"
	"fmt"
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
	AverageInputMax  uint8  // average number of inputs will be in [0, AverageInputMax]
	AverageOutputMax uint8  // average number of outputs  will be in [0, AverageOutputMax]
	distributionType int    // output Data size distribution (currently only support uniform)
	PublicKeyReuse   int    // (UTXO models) when a new output is created whether to reuse the input public key or
	// not will be decided from this such that probability of reuse = 1/publicKeyReuse
	TotalUsers     int // (ACC models) total number of users represented if this is a client
	TotalTx        int // total number of transactions if this is a peer
	TotalBlock     int // total number of blocks  if this is a peer
	TotalTempUsers int // maximum number of temp users

	TempUsers map[[sha256.Size]byte]TempUser
	TempPKs   map[[128]byte]int
	TempTxH   map[int][]byte // only used for origami accounts

	inputPointer           int // inputs are chosen from round-robin method
	outputPointer          int // inputs are chosen from round-robin method
	CurrentUsers           int
	CurrentUsersWithTemp   int
	CurrentOutputs         int // in Origami, CurrentUsers = CurrentOutputs
	CurrentOutputsWithTemp int // in Origami, CurrentUsers = CurrentOutputs
	DeletedOutputs         int //
	groupContext           key.Suite

	bnQ   *C.BIGNUM
	bnCtx *C.BN_CTX
	bnOne []byte

	enableIndexing bool

	db *sql.DB // sqlite database
}

func NewContext(exeId int, uType int, txType int, sigType int32, averageSize uint16, totalUsers int,
	averageInputMax uint8, averageOutputMax uint8, distributionType int, enableIndexing bool, publicKeyReuse int) ExeContext {
	log.SetFlags(log.LstdFlags | log.Lshortfile)

	ctx := ExeContext{
		exeId:                  exeId,
		uType:                  uType,
		txModel:                txType,
		payloadSize:            averageSize,
		AverageInputMax:        averageInputMax,
		AverageOutputMax:       averageOutputMax,
		distributionType:       distributionType,
		PublicKeyReuse:         publicKeyReuse,
		TotalUsers:             totalUsers,
		TotalBlock:             0,
		TotalTx:                0,
		inputPointer:           0,
		outputPointer:          0,
		CurrentUsers:           0,
		CurrentUsersWithTemp:   0,
		CurrentOutputs:         0,
		CurrentOutputsWithTemp: 0,
		DeletedOutputs:         0,
		TotalTempUsers:         10,
		TempUsers:              make(map[[sha256.Size]byte]TempUser),
		TempPKs:                make(map[[128]byte]int),
		TempTxH:                make(map[int][]byte),
		enableIndexing:         enableIndexing,
	}

	// generate group context
	rng := blake2xb.New(nil)
	ctx.groupContext = edwards25519.NewBlakeSHA256Ed25519WithRand(rng)

	// generate signature context
	ctx.sigContext = NewSigContext(sigType)
	ctx.sigContext.SigType = sigType

	if averageInputMax > averageOutputMax {
		log.Fatal("can't be AverageInputMax > AverageOutputMax")
	}

	if int(averageInputMax) >= totalUsers {
		log.Fatal("can't be AverageInputMax >= TotalUsers")
	}

	// generate all users for clients
	if uType == 1 {
		if ctx.txModel == 1 || ctx.txModel == 3 || ctx.txModel == 5 {
			ok, err := ctx.initClientDB()
			if !ok {
				log.Fatal("couldn't initiate the db:", err)
			}
		} else if ctx.txModel == 2 || ctx.txModel == 4 || ctx.txModel == 6 {
			ok, err := ctx.initClientDB()
			if !ok {
				log.Fatal("couldn't initiate the db:", err)
			}
		}
	} else if ctx.uType == 2 {
		ok, err := ctx.initPeerDB()
		if !ok {
			log.Fatal("couldn't initiate the db:", err)
		}
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

func (ctx *ExeContext) PrintDetails() {
	fmt.Println("tx model:", ctx.txModel)
	fmt.Println("sig type:", ctx.sigContext.SigType)
	fmt.Println("payload size:", ctx.payloadSize)
	fmt.Println("input max:", ctx.AverageInputMax)
	fmt.Println("output max:", ctx.AverageOutputMax)
	fmt.Println("transactions:", ctx.TotalTx)
	fmt.Println("users:", ctx.CurrentUsers)
	fmt.Println("outputs:", ctx.CurrentOutputs)
	fmt.Println("users with temp:", ctx.CurrentUsersWithTemp)
	fmt.Println("outputs with temp:", ctx.CurrentOutputsWithTemp)
}
