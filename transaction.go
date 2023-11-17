/**********************************************************************
 * Copyright (c) 2017 Jayamine Alupotha                               *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/

package txhelper

import (
	"bytes"
	"crypto/sha256"
	"go.dedis.ch/kyber/v3"
	"golang.org/x/crypto/sha3"
	"log"
	"math/rand"
	"strconv"
	"unsafe"
)

// #cgo CFLAGS: -g -Wall
// #cgo LDFLAGS: -lcrypto
// #include <stdlib.h>
// #include <stdint.h>
// #include <openssl/bn.h>
import "C"

type Transaction struct {
	N    int32    `json:"n"` // transaction index
	Txh  TxHeader `json:"t"` // transaction header
	Data AppData  `json:"d"` // application Data
}

/*
RandomTransaction outputs a transaction according to the sigType and txModel
txModel:1 - classicUTXO
txModel:2 - classicACC
txModel:3 - classicAUTXO
txModel:4 - classicAACC
txModel:5 - origamiUTXO
txModel:6 - origamiACC
*/
func (ctx *ExeContext) RandomTransaction() *Transaction {
	// variable sizes
	inSize := uint8(rand.Int() % int(ctx.averageInputMax+1))
	outSize := uint8(rand.Int()%int(ctx.averageOutputMax)) + 1

	var tx = new(Transaction)
	ctx.RandomAppData(&tx.Data, inSize, outSize, ctx.payloadSize)
	ctx.CreateTxHeader(&tx.Txh, &tx.Data)
	return tx
}

func (ctx *ExeContext) FixedTransaction(inSize uint8, outSize uint8) *Transaction {
	// variable sizes
	var tx = new(Transaction)
	ctx.RandomAppData(&tx.Data, inSize, outSize, ctx.payloadSize)
	ctx.CreateTxHeader(&tx.Txh, &tx.Data)
	return tx
}

func (ctx *ExeContext) checkUniqueness(tx *Transaction) (bool, *string) {
	// unique headers
	for j := 0; j < len(tx.Data.Inputs); j++ {
		for l := j + 1; l < len(tx.Data.Inputs); l++ {
			if bytes.Equal(tx.Data.Inputs[j].Header, tx.Data.Inputs[l].Header) {
				errM := " duplicate headers in inputs : " + strconv.FormatInt(int64(ctx.txModel), 10)
				return false, &errM
			}
		}
		for l := 0; l < len(tx.Data.Outputs); l++ {
			if bytes.Equal(tx.Data.Outputs[l].u.H, tx.Data.Inputs[j].Header) {
				errM := " duplicate headers in outputs : " + strconv.FormatInt(int64(ctx.txModel), 10)
				return false, &errM
			}
		}
	}

	// find outputs were duplicated
	var tempU User
	if ctx.uType == 2 {
		for i := 0; i < len(tx.Data.Outputs); i++ {
			// first check temps
			foundtemp, _, _, _ := ctx.getTempPeerOut(tx.Data.Outputs[i].header, &tempU)
			if !foundtemp {
				// then check db
				foundDB, _ := ctx.usedPeerOutHeader(tx.Data.Outputs[i].header)
				if foundDB {
					errM := " reused headers in outputs : " + strconv.FormatInt(int64(ctx.txModel), 10)
					return false, &errM
				}
			} else {
				errM := " reused headers in outputs : " + strconv.FormatInt(int64(ctx.txModel), 10)
				return false, &errM
			}
		}
	}

	if (ctx.txModel == 2 || ctx.txModel == 4 || ctx.txModel == 6) && ctx.uType == 2 {
		for j := len(tx.Data.Inputs); j < len(tx.Data.Outputs); j++ {
			found, _ := ctx.usedPeerOutPublicKey(tx.Data.Outputs[j].Pk)
			if found {
				errM := "used public keys in new accounts"
				return false, &errM
			}
		}
	}

	// unique accounts
	if ctx.txModel == 2 || ctx.txModel == 4 || ctx.txModel == 6 {
		for j := 0; j < len(tx.Data.Outputs); j++ {
			for l := j + 1; l < len(tx.Data.Outputs); l++ {
				if bytes.Equal(tx.Data.Outputs[j].Pk, tx.Data.Outputs[l].Pk) {
					errM := "duplicate pk in outputs"
					return false, &errM
				}
			}
		}
	}
	return true, nil
}

// VerifyIncomingTransaction verifies a raw transaction
func (ctx *ExeContext) VerifyIncomingTransaction(tx *Transaction) (bool, *string) {
	if ctx.uType == 2 {
		_, err := ctx.PrepareAppDataPeer(&tx.Data)
		if err != nil {
			errM := err.Error()
			return false, &errM
		}
	} else if ctx.uType == 1 {
		_, err := ctx.PrepareAppDataClient(&tx.Data)
		if err != nil {
			errM := err.Error()
			return false, &errM
		}
	}

	ok, err := ctx.checkUniqueness(tx)
	if !ok {
		return false, err
	}

	return ctx.VerifyTxHeader(&tx.Txh, &tx.Data)
}

// VerifyIncomingTransactionWithTemp verifies a raw transaction including temps
func (ctx *ExeContext) VerifyIncomingTransactionWithTemp(tx *Transaction) (bool, *string) {
	if ctx.uType == 2 {
		_, err := ctx.PrepareAppDataPeerWithTemps(&tx.Data)
		if err != nil {
			errM := err.Error()
			return false, &errM
		}
	} else if ctx.uType == 1 {
		_, err := ctx.PrepareAppDataClient(&tx.Data)
		if err != nil {
			errM := err.Error()
			return false, &errM
		}
	}

	ok, err := ctx.checkUniqueness(tx)
	if !ok {
		return false, err
	}

	return ctx.VerifyTxHeader(&tx.Txh, &tx.Data)
}

// InsertTxHeader adds a transaction header, which was verified before.
func (ctx *ExeContext) InsertTxHeader(txn int, tx *Transaction) (bool, *string) {
	if ctx.uType == 2 {
		ok, err := ctx.insertPeerTxHeader(txn, tx)
		if !ok {
			errM := "could not insert header:" + err.Error()
			return false, &errM
		}
		ctx.TotalTx += 1
	} else {
		log.Fatal("only peers can add txHeaders")
	}
	return true, nil
}

// GetTxHeaderIdentifier outputs an identifier a special hash to be included into the tx block hash computation
// for classics: hash is the hash of the entire transaction
// for origami: hash is the hash of (activity, all account pks)
func (ctx *ExeContext) GetTxHeaderIdentifier(tx *Transaction, txBytes []byte) (bool, []byte, *string) {
	var txIdentifier []byte
	if ctx.txModel >= 1 && ctx.txModel <= 4 {
		if txBytes == nil {
			txBytes = ctx.ToBytes(tx)
		}
		hasher := sha3.New256()
		txIdentifier = hasher.Sum(txBytes)
	} else if ctx.txModel == 5 {
		hasher := sha3.New256()
		if len(tx.Txh.activityProof) != 33 {
			errM := "activity is empty. Did yoy verify the transaction?"
			return false, nil, &errM
		}
		hasher.Write(tx.Txh.activityProof)
		hasher.Write(tx.Txh.excessPK)
		txIdentifier = hasher.Sum(tx.Txh.Kyber[0])
	} else if ctx.txModel == 6 {
		hasher := sha3.New256()
		if len(tx.Txh.activityProof) != 33 {
			errM := "activity is empty. Did yoy verify the transaction?"
			return false, nil, &errM
		}
		hasher.Write(tx.Txh.activityProof)
		for i := 0; i < len(tx.Data.Outputs); i++ {
			hasher.Write(tx.Data.Outputs[i].Pk)
		}
		txIdentifier = hasher.Sum(nil)
	}
	return true, txIdentifier, nil
}

// VerifyStoredAllTransaction verifies all stored transactions
func (ctx *ExeContext) VerifyStoredAllTransaction() (bool, *string) {

	if ctx.txModel >= 1 && ctx.txModel <= 4 {
		//set used to 0
		used := make([]uint8, ctx.CurrentOutputs)
		usedHeader := make([][]byte, ctx.CurrentOutputs)
		//verify all tx from 0 while resetting used
		for i := 0; i < ctx.TotalTx; i++ {
			tx, ok, err := ctx.getStoredTx(i)
			if !ok {
				errM := err.Error()
				return false, &errM
			}
			// unique headers
			for j := 0; j < len(tx.Data.Inputs); j++ {
				//check if they were used before
				if used[tx.Data.Inputs[j].u.id] != 0 && bytes.Equal(usedHeader[tx.Data.Inputs[j].u.id], tx.Data.Inputs[j].Header) {
					errM := "double spent inputs"
					return false, &errM
				}
				used[tx.Data.Inputs[j].u.id] += 1
				usedHeader[tx.Data.Inputs[j].u.id] = tx.Data.Inputs[j].Header

				// unique headers
				for l := j + 1; l < len(tx.Data.Inputs); l++ {
					if bytes.Equal(tx.Data.Inputs[j].Header, tx.Data.Inputs[l].Header) {
						errM := "duplicate headers in inputs"
						return false, &errM
					}
				}
				for l := 0; l < len(tx.Data.Outputs); l++ {
					if bytes.Equal(tx.Data.Inputs[j].Header, tx.Data.Outputs[l].u.H) {
						errM := "duplicate headers in inputs/outputs"
						return false, &errM
					}
				}
			}
			// unique accounts
			if ctx.txModel == 2 || ctx.txModel == 4 || ctx.txModel == 6 {
				for j := 0; j < len(tx.Data.Outputs); j++ {
					for l := j + 1; l < len(tx.Data.Outputs); l++ {
						if bytes.Equal(tx.Data.Outputs[j].Pk, tx.Data.Outputs[l].Pk) {
							errM := "duplicate accounts"
							return false, &errM
						}
					}
				}
			}
			val, errM := ctx.VerifyTxHeader(&tx.Txh, &tx.Data)
			if !val {
				return false, errM
			}
		}

	} else if ctx.txModel == 5 {
		temp := C.BN_new()
		totalD := C.BN_new()
		C.BN_bin2bn((*C.uchar)(unsafe.Pointer(&ctx.bnOne[0])), 33, temp)
		C.BN_copy(totalD, temp)
		var txh TxHeader
		var pk Pubkey
		var totalExcess kyber.Point
		buffer := make([]byte, 33+ctx.sigContext.PkSize)
		for i := 0; i < ctx.TotalTx; i++ {
			val, err := ctx.getTxHeader(i, &txh)
			if !val {
				errM := "Error in tx header data:" + err.Error()
				return false, &errM
			}
			copy(buffer, txh.activityProof)
			copy(buffer[33:], txh.excessPK)

			ctx.sigContext.unmarshelPublicKeysFromBytes(&pk, txh.excessPK)
			if !ctx.sigContext.verify(&pk, buffer, txh.Kyber[0]) {
				err := "invalid sig"
				return false, &err
			}
			if i == 0 {
				totalExcess = pk.kyber.Clone()
			} else {
				totalExcess.Add(totalExcess, pk.kyber)
			}
			C.BN_bin2bn((*C.uchar)(unsafe.Pointer(&txh.activityProof[0])), 33, temp)
			C.BN_mod_mul(totalD, totalD, temp, ctx.bnQ, ctx.bnCtx)
		}

		val, excessBytes, HProd, err := ctx.getAggregateOutData()
		if !val {
			errM := "Error in aggregate data:" + err.Error()
			return false, &errM
		}

		userHProd := make([]byte, 33)
		C.BN_bn2binpad(totalD, (*C.uchar)(unsafe.Pointer(&userHProd[0])), 33)
		if !bytes.Equal(userHProd, HProd) {
			errM := "Error in aggregate delta"
			return false, &errM
		}

		userHProd, err = totalExcess.MarshalBinary()
		if err != nil {
			errM := "Error while aggregating pk" + err.Error()
			return false, &errM
		}
		if !bytes.Equal(excessBytes, userHProd) {
			errM := "Error in aggregate pk"
			return false, &errM
		}

	} else if ctx.txModel == 6 {
		var user User
		temp := C.BN_new()
		d := C.BN_new()
		C.BN_set_bit(temp, 255)
		C.BN_set_bit(d, 255)

		activities, activityProd, err := ctx.setActivityTable()
		if err != nil {
			errM := err.Error()
			return false, &errM
		}
		for i := 0; i < ctx.CurrentUsers; i++ {
			found, _, err := ctx.getPeerOutFromID(i, &user)
			if !found {
				errM := "user doesn't exist:" + err.Error()
				return false, &errM
			}
			// check the validity of activities
			if !bytes.Equal(activities[i].Bytes(), user.UDelta) {
				errM := "total user activities do not match"
				return false, &errM
			}
			if int(user.N) != len(user.Txns) {
				errM := "total user transaction count does not match"
				return false, &errM
			}
			// prod of user identifiers
			C.BN_bin2bn((*C.uchar)(unsafe.Pointer(&user.H[0])), 32, temp)
			C.BN_mod_mul(d, d, temp, ctx.bnQ, ctx.bnCtx)
			C.BN_clear(temp)

			// signature
			buf := new(bytes.Buffer)
			keybuffer := new(bytes.Buffer)
			var pk Pubkey

			buf.Write(user.Keys)
			buf.WriteByte(user.N)
			buf.Write(user.Data)
			buf.Write(user.UDelta)

			//buf.Write(ctx.computeUserWmark(user.UDelta, user.H))
			if ctx.sigContext.SigType == 1 || ctx.sigContext.SigType == 2 {
				keybuffer.Write(user.Keys)
				ctx.sigContext.unmarshelPublicKeys(&pk, keybuffer)
				if ctx.sigContext.verify(&pk, buf.Bytes(), user.sig) == false {
					errM := "invalid sig " + strconv.FormatInt(int64(i), 10)
					return false, &errM
				}
				keybuffer.Reset()
			}
			buf.Reset()
		}
		// prof activities ?= prod user identifiers
		userHProd := make([]byte, 33)
		C.BN_bn2binpad(d, (*C.uchar)(unsafe.Pointer(&userHProd[0])), 33)
		if !bytes.Equal(userHProd, activityProd) {
			errM := "products of activities do not match"
			return false, &errM
		}
	}

	return true, nil
}

func (ctx *ExeContext) ToBytes(tx *Transaction) []byte {
	buffer := new(bytes.Buffer)

	buffer.WriteByte(uint8(len(tx.Data.Inputs) % 0xff))
	buffer.WriteByte(uint8(len(tx.Data.Outputs) % 0xff))

	for i := 0; i < len(tx.Data.Inputs); i++ {
		buffer.Write(tx.Data.Inputs[i].Header)
	}
	for i := 0; i < len(tx.Data.Outputs); i++ {
		if i >= len(tx.Data.Inputs) || ctx.txModel == 1 || ctx.txModel == 3 || ctx.txModel == 5 {
			buffer.Write(tx.Data.Outputs[i].Pk)
			buffer.WriteByte(tx.Data.Outputs[i].N)
		}
		buffer.Write(tx.Data.Outputs[i].Data)
	}
	buffer.WriteByte(uint8(len(tx.Txh.Kyber) % 0xff))
	for i := 0; i < len(tx.Txh.Kyber); i++ {
		buffer.Write(tx.Txh.Kyber[i])
	}

	return buffer.Bytes()
}

func (ctx *ExeContext) FromBytes(arr []byte, tx *Transaction) bool {
	if len(arr) <= 2 {
		return false
	}
	var i uint8
	pointer := 0
	inSize := arr[pointer]
	tx.Data.Inputs = make([]InputData, inSize)
	pointer += 1
	outSize := arr[pointer]
	tx.Data.Outputs = make([]OutputData, outSize)
	pointer += 1

	if len(arr) < pointer+sha256.Size*int(inSize) {
		return false
	}

	for i = 0; i < inSize; i++ {
		tx.Data.Inputs[i].Header = make([]byte, sha256.Size)
		copy(tx.Data.Inputs[i].Header, arr[pointer:])
		pointer += sha256.Size
	}

	if ctx.txModel == 1 || ctx.txModel == 3 || ctx.txModel == 5 {
		if len(arr) < pointer+(int(ctx.sigContext.PkSize)+1)*(int(outSize)-int(inSize))+int(ctx.payloadSize)*int(outSize) {
			return false
		}
	} else {
		if len(arr) < pointer+int(ctx.payloadSize)*int(outSize) {
			return false
		}
	}

	for i = 0; i < outSize; i++ {
		if int(i) >= len(tx.Data.Inputs) || ctx.txModel == 1 || ctx.txModel == 3 || ctx.txModel == 5 {
			tx.Data.Outputs[i].Pk = make([]byte, ctx.sigContext.PkSize)
			copy(tx.Data.Outputs[i].Pk, arr[pointer:])
			pointer += int(ctx.sigContext.PkSize)

			tx.Data.Outputs[i].N = arr[pointer]
			pointer += 1
		}

		tx.Data.Outputs[i].Data = make([]byte, ctx.payloadSize)
		copy(tx.Data.Outputs[i].Data, arr[pointer:])
		pointer += int(ctx.payloadSize)
	}

	if len(arr) < pointer+1 {
		return false
	}

	sigSize := arr[pointer]
	pointer += 1

	if len(arr) < pointer+int(sigSize)*int(ctx.sigContext.SigSize) {
		return false
	}

	tx.Txh.Kyber = make([]Signature, sigSize)
	for i = 0; i < sigSize; i++ {
		tx.Txh.Kyber[i] = make([]byte, ctx.sigContext.SigSize)
		copy(tx.Txh.Kyber[i], arr[pointer:])
		pointer += int(ctx.sigContext.SigSize)
	}
	return true
}
