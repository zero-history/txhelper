/**********************************************************************
 * Copyright (c) 2017 Jayamine Alupotha                               *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/

package txhelper

import (
	"bytes"
	"log"
)

// #cgo CFLAGS: -g -Wall
// #cgo LDFLAGS: -lcrypto -lsecp256k1 -lexelayers
// #include <stdlib.h>
// #include <stdint.h>
// #include <openssl/bn.h>
import "C"

type TxHeader struct {
	Kyber         []Signature `json:"k"` // signatures
	activityProof []byte
	excessPK      []byte
}

// CreateTxHeader creates a transaction header
func (ctx *ExeContext) CreateTxHeader(txh *TxHeader, data *AppData) {
	switch ctx.txModel {
	case 1:
		ctx.utxoClassicTxHeader(txh, data)
	case 2:
		ctx.accClassicTxHeader(txh, data)
	case 3:
		ctx.utxoAccountableClassicTxHeader(txh, data)
	case 4:
		ctx.accAccountableClassicTxHeader(txh, data)
	case 5:
		ctx.utxoOrigamiTxHeader(txh, data)
	case 6:
		ctx.accOrigamiTxHeader(txh, data)
	default:
		log.Fatal("unknown txModel")
	}
}

// VerifyTxHeader verifies a transaction header
func (ctx *ExeContext) VerifyTxHeader(txh *TxHeader, data *AppData) (bool, *string) {
	valid := false
	var err *string
	switch ctx.txModel {
	case 1:
		valid, err = ctx.verifyUtxoClassicTxHeader(txh, data)
	case 2:
		valid, err = ctx.verifyAccClassicTxHeader(txh, data)
	case 3:
		valid, err = ctx.verifyUtxoAccountableClassicTxHeader(txh, data)
	case 4:
		valid, err = ctx.verifyAccAccountableClassicTxHeader(txh, data)
	case 5:
		valid, err = ctx.verifyUtxoOrigamiTxHeader(txh, data)
	case 6:
		valid, err = ctx.verifyAccOrigamiTxHeader(txh, data)
	default:
		log.Fatal("unknown txModel")
	}
	return valid, err
}

func (ctx *ExeContext) utxoClassicTxHeader(txh *TxHeader, data *AppData) {
	buffer := new(bytes.Buffer)
	var keys SigKeyPair

	for i := 0; i < len(data.Inputs); i++ {
		buffer.Write(data.Inputs[i].Header)
	}
	for i := 0; i < len(data.Outputs); i++ {
		buffer.Write(data.Outputs[i].Pk)
		buffer.WriteByte(data.Outputs[i].N)
		buffer.Write(data.Outputs[i].Data)
	}

	if ctx.sigContext.SigType == 1 {
		// if there are no inputs, all output owners must sign
		if len(data.Inputs) == 0 {
			txh.Kyber = make([]Signature, len(data.Outputs))
			for i := 0; i < len(data.Outputs); i++ {
				ctx.sigContext.unmarshelKeys(&keys, data.Outputs[i].u.Keys)
				txh.Kyber[i] = ctx.sigContext.sign(&keys, buffer.Bytes())
			}
		} else { // otherwise, only input owners sign
			txh.Kyber = make([]Signature, len(data.Inputs))
			for i := 0; i < len(data.Inputs); i++ {
				ctx.sigContext.unmarshelKeys(&keys, data.Inputs[i].u.Keys)
				txh.Kyber[i] = ctx.sigContext.sign(&keys, buffer.Bytes())
			}
		}
	}

	if ctx.sigContext.SigType == 2 {
		// if there are no inputs, all output owners must sign
		var sigs []Signature
		if len(data.Inputs) == 0 {
			sigs = make([]Signature, len(data.Outputs))
			for i := 0; i < len(data.Outputs); i++ {
				ctx.sigContext.unmarshelKeys(&keys, data.Outputs[i].u.Keys)
				sigs[i] = ctx.sigContext.sign(&keys, buffer.Bytes())
			}
		} else { // otherwise, only input owners sign
			sigs = make([]Signature, len(data.Inputs))
			for i := 0; i < len(data.Inputs); i++ {
				ctx.sigContext.unmarshelKeys(&keys, data.Inputs[i].u.Keys)
				sigs[i] = ctx.sigContext.sign(&keys, buffer.Bytes())
			}
		}
		txh.Kyber = make([]Signature, 1)
		txh.Kyber[0] = ctx.sigContext.aggregateSignatures(sigs)
	}
}

func (ctx *ExeContext) verifyUtxoClassicTxHeader(txh *TxHeader, data *AppData) (bool, *string) {
	buffer := new(bytes.Buffer)
	var pk Pubkey
	var err string

	for i := 0; i < len(data.Inputs); i++ {
		buffer.Write(data.Inputs[i].Header)
	}
	for i := 0; i < len(data.Outputs); i++ {
		buffer.Write(data.Outputs[i].Pk)
		buffer.WriteByte(data.Outputs[i].N)
		buffer.Write(data.Outputs[i].Data)
	}

	if ctx.sigContext.SigType == 1 {
		if len(data.Inputs) == 0 {
			for i := 0; i < len(data.Outputs); i++ {
				ctx.sigContext.unmarshelPublicKeysFromBytes(&pk, data.Outputs[i].Pk)
				if ctx.sigContext.verify(&pk, buffer.Bytes(), txh.Kyber[i]) == false {
					err = "invalid sig"
					return false, &err
				}
			}
		} else {
			for i := 0; i < len(data.Inputs); i++ {
				ctx.sigContext.unmarshelPublicKeysFromBytes(&pk, data.Inputs[i].u.Keys[:ctx.sigContext.PkSize])
				if ctx.sigContext.verify(&pk, buffer.Bytes(), txh.Kyber[i]) == false {
					err = "invalid sig"
					return false, &err
				}
			}
		}
	}

	if ctx.sigContext.SigType == 2 {
		var pks []Pubkey
		if len(data.Inputs) == 0 {
			pks = make([]Pubkey, len(data.Outputs))
			for i := 0; i < len(data.Outputs); i++ {
				ctx.sigContext.unmarshelPublicKeysFromBytes(&pks[i], data.Outputs[i].Pk)
			}
		} else {
			pks = make([]Pubkey, len(data.Inputs))
			for i := 0; i < len(data.Inputs); i++ {
				ctx.sigContext.unmarshelPublicKeysFromBytes(&pks[i], data.Inputs[i].u.Keys)
			}
		}
		if !ctx.sigContext.batchVerify(pks, buffer.Bytes(), txh.Kyber[0]) {
			err = "invalid aggregate sig"
			return false, &err
		}
	}

	return true, nil
}

func (ctx *ExeContext) accClassicTxHeader(txh *TxHeader, data *AppData) {
	buffer := new(bytes.Buffer)
	var keys SigKeyPair

	for i := 0; i < len(data.Inputs); i++ {
		buffer.Write(data.Inputs[i].Header)
	}
	for i := 0; i < len(data.Outputs); i++ {
		buffer.Write(data.Outputs[i].Pk)
		buffer.WriteByte(data.Outputs[i].N)
		buffer.Write(data.Outputs[i].Data)
	}

	if ctx.sigContext.SigType == 1 {
		if len(data.Inputs) == 0 { // output owners must sign if there are no inputs
			txh.Kyber = make([]Signature, len(data.Outputs))
			for i := 0; i < len(data.Outputs); i++ {
				ctx.sigContext.unmarshelKeys(&keys, data.Outputs[i].u.Keys)
				txh.Kyber[i] = ctx.sigContext.sign(&keys, buffer.Bytes())
			}
		} else { // Otherwise, only input owners sign
			txh.Kyber = make([]Signature, len(data.Inputs))
			for i := 0; i < len(data.Inputs); i++ {
				ctx.sigContext.unmarshelKeys(&keys, data.Inputs[i].u.Keys)
				txh.Kyber[i] = ctx.sigContext.sign(&keys, buffer.Bytes())
			}
		}
	}

	if ctx.sigContext.SigType == 2 {
		var sigs []Signature
		if len(data.Inputs) == 0 { // output owners must sign if there are no inputs
			sigs = make([]Signature, len(data.Outputs))
			for i := 0; i < len(data.Outputs); i++ {
				ctx.sigContext.unmarshelKeys(&keys, data.Outputs[i].u.Keys)
				sigs[i] = ctx.sigContext.sign(&keys, buffer.Bytes())
			}
		} else { // Otherwise, only input owners sign
			sigs = make([]Signature, len(data.Inputs))
			for i := 0; i < len(data.Inputs); i++ {
				ctx.sigContext.unmarshelKeys(&keys, data.Inputs[i].u.Keys)
				sigs[i] = ctx.sigContext.sign(&keys, buffer.Bytes())
			}
		}
		txh.Kyber = make([]Signature, 1)
		txh.Kyber[0] = ctx.sigContext.aggregateSignatures(sigs)
	}
}

func (ctx *ExeContext) verifyAccClassicTxHeader(txh *TxHeader, data *AppData) (bool, *string) {
	buffer := new(bytes.Buffer)
	var pk Pubkey
	var err string

	for i := 0; i < len(data.Inputs); i++ {
		buffer.Write(data.Inputs[i].Header)
	}
	for i := 0; i < len(data.Outputs); i++ {
		buffer.Write(data.Outputs[i].Pk)
		buffer.WriteByte(data.Outputs[i].N)
		buffer.Write(data.Outputs[i].Data)
	}

	if ctx.sigContext.SigType == 1 {
		if len(data.Inputs) == 0 {
			for i := 0; i < len(data.Outputs); i++ {
				ctx.sigContext.unmarshelPublicKeysFromBytes(&pk, data.Outputs[i].Pk)
				if ctx.sigContext.verify(&pk, buffer.Bytes(), txh.Kyber[i]) == false {
					err = "invalid sig"
					return false, &err
				}
			}

		} else {
			for i := 0; i < len(data.Inputs); i++ {
				ctx.sigContext.unmarshelPublicKeysFromBytes(&pk, data.Inputs[i].u.Keys[:ctx.sigContext.PkSize])
				if ctx.sigContext.verify(&pk, buffer.Bytes(), txh.Kyber[i]) == false {
					err = "invalid sig"
					return false, &err
				}
			}
		}
	}
	if ctx.sigContext.SigType == 2 {
		var pks []Pubkey
		if len(data.Inputs) == 0 {
			pks = make([]Pubkey, len(data.Outputs))
			for i := 0; i < len(data.Outputs); i++ {
				ctx.sigContext.unmarshelPublicKeysFromBytes(&pks[i], data.Outputs[i].Pk)
			}

		} else {
			pks = make([]Pubkey, len(data.Inputs))
			for i := 0; i < len(data.Inputs); i++ {
				ctx.sigContext.unmarshelPublicKeysFromBytes(&pks[i], data.Inputs[i].u.Keys[:ctx.sigContext.PkSize])
			}
		}
		if !ctx.sigContext.batchVerify(pks, buffer.Bytes(), txh.Kyber[0]) {
			err = "invalid aggregate sig"
			return false, &err
		}
	}
	return true, nil
}

func (ctx *ExeContext) utxoAccountableClassicTxHeader(txh *TxHeader, data *AppData) {
	buffer := new(bytes.Buffer)
	var keys SigKeyPair
	var sig Signature

	for i := 0; i < len(data.Inputs); i++ {
		buffer.Write(data.Inputs[i].Header)
	}
	for i := 0; i < len(data.Outputs); i++ {
		buffer.Write(data.Outputs[i].Pk)
		buffer.WriteByte(data.Outputs[i].N)
		buffer.Write(data.Outputs[i].Data)
	}

	var sigs []Signature
	if ctx.sigContext.SigType == 1 {
		txh.Kyber = make([]Signature, len(data.Inputs))
	}
	if ctx.sigContext.SigType == 2 {
		sigs = make([]Signature, len(data.Inputs))
	}
	for i := 0; i < len(data.Inputs); i++ {
		if ctx.sigContext.SigType == 1 || ctx.sigContext.SigType == 2 {
			ctx.sigContext.unmarshelKeys(&keys, data.Inputs[i].u.Keys)
			if ctx.sigContext.SigType == 1 {
				txh.Kyber[i] = ctx.sigContext.sign(&keys, buffer.Bytes())
			}
			if ctx.sigContext.SigType == 2 {
				sigs[i] = ctx.sigContext.sign(&keys, buffer.Bytes())
			}
		}
	}
	for i := 0; i < len(data.Outputs); i++ {
		if ctx.sigContext.SigType == 1 || ctx.sigContext.SigType == 2 {
			found := false
			for j := 0; j < len(data.Inputs); j++ {
				if bytes.Equal(data.Inputs[j].u.Keys[:ctx.sigContext.PkSize],
					data.Outputs[i].Pk) == true {
					found = true
					break
				}
			}
			if !found {
				ctx.sigContext.unmarshelKeys(&keys, data.Outputs[i].u.Keys)
				sig = ctx.sigContext.sign(&keys, buffer.Bytes())
				if ctx.sigContext.SigType == 1 {
					txh.Kyber = append(txh.Kyber, sig)
				}
				if ctx.sigContext.SigType == 2 {
					sigs = append(sigs, sig)
				}
			}
		}
	}
	if ctx.sigContext.SigType == 2 {
		txh.Kyber = make([]Signature, 1)
		txh.Kyber[0] = ctx.sigContext.aggregateSignatures(sigs)
	}
}

func (ctx *ExeContext) verifyUtxoAccountableClassicTxHeader(txh *TxHeader, data *AppData) (bool, *string) {
	buffer := new(bytes.Buffer)
	var pk Pubkey
	var err string

	for i := 0; i < len(data.Inputs); i++ {
		buffer.Write(data.Inputs[i].Header)
	}
	for i := 0; i < len(data.Outputs); i++ {
		buffer.Write(data.Outputs[i].Pk)
		buffer.WriteByte(data.Outputs[i].N)
		buffer.Write(data.Outputs[i].Data)
	}

	var pks []Pubkey
	if ctx.sigContext.SigType == 2 {
		pks = make([]Pubkey, len(data.Inputs))
	}

	for i := 0; i < len(data.Inputs); i++ {
		if ctx.sigContext.SigType == 1 || ctx.sigContext.SigType == 2 {
			if ctx.sigContext.SigType == 1 {
				ctx.sigContext.unmarshelPublicKeysFromBytes(&pk, data.Inputs[i].u.Keys[:ctx.sigContext.PkSize])
				if ctx.sigContext.verify(&pk, buffer.Bytes(), txh.Kyber[i]) == false {
					err = "invalid sig"
					return false, &err
				}
			}
			if ctx.sigContext.SigType == 2 {
				ctx.sigContext.unmarshelPublicKeysFromBytes(&pks[i], data.Inputs[i].u.Keys[:ctx.sigContext.PkSize])
			}
		}
	}
	j := 0
	for i := 0; i < len(data.Outputs); i++ {
		if ctx.sigContext.SigType == 1 || ctx.sigContext.SigType == 2 {
			found := false
			for j := 0; j < len(data.Inputs); j++ {
				if bytes.Equal(data.Inputs[j].u.Keys[:ctx.sigContext.PkSize], data.Outputs[i].Pk) == true {
					found = true
					break
				}
			}
			if !found {
				if ctx.sigContext.SigType == 1 {
					ctx.sigContext.unmarshelPublicKeysFromBytes(&pk, data.Outputs[i].Pk)
					if ctx.sigContext.verify(&pk, buffer.Bytes(), txh.Kyber[j+len(data.Inputs)]) == false {
						err = "invalid sig"
						return false, &err
					}
				}
				if ctx.sigContext.SigType == 2 {
					ctx.sigContext.unmarshelPublicKeysFromBytes(&pk, data.Outputs[i].Pk)
					pks = append(pks, pk)
				}
				j++
			}
		}
	}
	if ctx.sigContext.SigType == 2 {
		if !ctx.sigContext.batchVerify(pks, buffer.Bytes(), txh.Kyber[0]) {
			err = "invalid aggregate sig"
			return false, &err
		}
	}
	return true, nil
}

func (ctx *ExeContext) accAccountableClassicTxHeader(txh *TxHeader, data *AppData) {
	buffer := new(bytes.Buffer)
	var keys SigKeyPair

	for i := 0; i < len(data.Inputs); i++ {
		buffer.Write(data.Inputs[i].Header)
	}
	for i := 0; i < len(data.Outputs); i++ {
		buffer.Write(data.Outputs[i].Pk)
		buffer.WriteByte(data.Outputs[i].N)
		buffer.Write(data.Outputs[i].Data)
	}

	var sigs []Signature
	if ctx.sigContext.SigType == 1 {
		txh.Kyber = make([]Signature, len(data.Outputs))
	}
	if ctx.sigContext.SigType == 2 {
		sigs = make([]Signature, len(data.Outputs))
	}

	for i := 0; i < len(data.Inputs); i++ {
		if ctx.sigContext.SigType == 1 {
			ctx.sigContext.unmarshelKeys(&keys, data.Inputs[i].u.Keys)
			txh.Kyber[i] = ctx.sigContext.sign(&keys, buffer.Bytes())
		}
		if ctx.sigContext.SigType == 2 {
			ctx.sigContext.unmarshelKeys(&keys, data.Inputs[i].u.Keys)
			sigs[i] = ctx.sigContext.sign(&keys, buffer.Bytes())
		}
	}
	for i := len(data.Inputs); i < len(data.Outputs); i++ {
		if ctx.sigContext.SigType == 1 {
			ctx.sigContext.unmarshelKeys(&keys, data.Outputs[i].u.Keys)
			txh.Kyber[i] = ctx.sigContext.sign(&keys, buffer.Bytes())
		}
		if ctx.sigContext.SigType == 2 {
			ctx.sigContext.unmarshelKeys(&keys, data.Outputs[i].u.Keys)
			sigs[i] = ctx.sigContext.sign(&keys, buffer.Bytes())
		}
	}

	if ctx.sigContext.SigType == 2 {
		txh.Kyber = make([]Signature, 1)
		txh.Kyber[0] = ctx.sigContext.aggregateSignatures(sigs)
	}
}

func (ctx *ExeContext) verifyAccAccountableClassicTxHeader(txh *TxHeader, data *AppData) (bool, *string) {
	buffer := new(bytes.Buffer)
	var pk Pubkey
	var err string

	for i := 0; i < len(data.Inputs); i++ {
		buffer.Write(data.Inputs[i].Header)
	}
	for i := 0; i < len(data.Outputs); i++ {
		buffer.Write(data.Outputs[i].Pk)
		buffer.WriteByte(data.Outputs[i].N)
		buffer.Write(data.Outputs[i].Data)
	}

	var pks []Pubkey
	if ctx.sigContext.SigType == 2 {
		pks = make([]Pubkey, len(data.Outputs))
	}
	for i := 0; i < len(data.Inputs); i++ {
		if ctx.sigContext.SigType == 1 {
			ctx.sigContext.unmarshelPublicKeysFromBytes(&pk, data.Inputs[i].u.Keys[:ctx.sigContext.PkSize])
			if ctx.sigContext.verify(&pk, buffer.Bytes(), txh.Kyber[i]) == false {
				err = "invalid sig"
				return false, &err
			}
		}
		if ctx.sigContext.SigType == 2 {
			ctx.sigContext.unmarshelPublicKeysFromBytes(&pks[i], data.Inputs[i].u.Keys[:ctx.sigContext.PkSize])
		}
	}
	for i := len(data.Inputs); i < len(data.Outputs); i++ {
		if ctx.sigContext.SigType == 1 {
			ctx.sigContext.unmarshelPublicKeysFromBytes(&pk, data.Outputs[i].Pk)
			if ctx.sigContext.verify(&pk, buffer.Bytes(), txh.Kyber[i]) == false {
				err = "invalid sig"
				return false, &err
			}
		}
		if ctx.sigContext.SigType == 2 {
			ctx.sigContext.unmarshelPublicKeysFromBytes(&pks[i], data.Outputs[i].Pk)
		}
	}
	if ctx.sigContext.SigType == 2 {
		if !ctx.sigContext.batchVerify(pks, buffer.Bytes(), txh.Kyber[0]) {
			err = "invalid aggregate sig"
			return false, &err
		}
	}
	return true, nil
}

func (ctx *ExeContext) utxoOrigamiTxHeader(txh *TxHeader, data *AppData) {
	buffer := new(bytes.Buffer)

	negkeysP := make([]*SigKeyPair, len(data.Inputs))
	keysP := make([]*SigKeyPair, len(data.Outputs))
	negkeys := make([]SigKeyPair, len(data.Inputs))
	pluskeys := make([]SigKeyPair, len(data.Outputs))

	// create keys
	for i := 0; i < len(data.Inputs); i++ {
		ctx.sigContext.unmarshelKeys(&negkeys[i], data.Inputs[i].u.Keys)
		ctx.sigContext.selfMultiplyKeyPairs(&negkeys[i], data.Inputs[i].Header)
		negkeysP[i] = &negkeys[i]
	}
	// compute header
	for i := 0; i < len(data.Outputs); i++ {
		data.Outputs[i].header = ctx.computeOutIdentifier(data.Outputs[i].Pk, data.Outputs[i].N, data.Outputs[i].Data)
		ctx.sigContext.unmarshelKeys(&pluskeys[i], data.Outputs[i].u.Keys)
		ctx.sigContext.selfMultiplyKeyPairs(&pluskeys[i], data.Outputs[i].header)
		keysP[i] = &pluskeys[i]
	}
	txh.activityProof = ctx.computeAppActivity(data) // to compute header - must be after computeOutIdentifier
	txh.excessPK = ctx.sigContext.diffPKFromPairs(keysP, negkeysP)

	txh.Kyber = make([]Signature, 1)

	if len(txh.activityProof) != 33 {
		log.Fatal("error in activities")
	}

	var pk Pubkey
	ctx.sigContext.unmarshelPublicKeysFromBytes(&pk, txh.excessPK)

	buffer.Write(txh.activityProof)
	buffer.Write(txh.excessPK)
	txh.Kyber[0] = ctx.sigContext.diffSign(keysP, negkeysP, &pk, buffer.Bytes())
}

func (ctx *ExeContext) verifyUtxoOrigamiTxHeader(txh *TxHeader, data *AppData) (bool, *string) {
	buffer := new(bytes.Buffer)

	negkeysP := make([]*Pubkey, len(data.Inputs))
	keysP := make([]*Pubkey, len(data.Outputs))
	negkeys := make([]Pubkey, len(data.Inputs))
	pluskeys := make([]Pubkey, len(data.Outputs))

	// create keys
	for i := 0; i < len(data.Inputs); i++ {
		ctx.sigContext.unmarshelPublicKeysFromBytes(&negkeys[i], data.Inputs[i].u.Keys[:ctx.sigContext.PkSize])
		ctx.sigContext.selfMultiplyPubKey(&negkeys[i], data.Inputs[i].Header)
		negkeysP[i] = &negkeys[i]
	}
	// compute header
	for i := 0; i < len(data.Outputs); i++ {
		data.Outputs[i].header = ctx.computeOutIdentifier(data.Outputs[i].Pk, data.Outputs[i].N, data.Outputs[i].Data)
		ctx.sigContext.unmarshelPublicKeysFromBytes(&pluskeys[i], data.Outputs[i].Pk)
		ctx.sigContext.selfMultiplyPubKey(&pluskeys[i], data.Outputs[i].header)
		keysP[i] = &pluskeys[i]
	}
	txh.activityProof = ctx.computeAppActivity(data) // to compute header - must be after computeOutIdentifier
	txh.excessPK = ctx.sigContext.diffPK(keysP, negkeysP)

	buffer.Write(txh.activityProof)
	buffer.Write(txh.excessPK)

	var pk Pubkey
	ctx.sigContext.unmarshelPublicKeysFromBytes(&pk, txh.excessPK)
	if !ctx.sigContext.verify(&pk, buffer.Bytes(), txh.Kyber[0]) {
		err := "invalid sig"
		return false, &err
	}

	return true, nil
}

func (ctx *ExeContext) accOrigamiTxHeader(txh *TxHeader, data *AppData) {
	buf := new(bytes.Buffer)
	var keys SigKeyPair

	// compute header
	for i := 0; i < len(data.Outputs); i++ {
		data.Outputs[i].header = ctx.computeOutIdentifier(data.Outputs[i].Pk, data.Outputs[i].N, data.Outputs[i].Data)
	}

	txh.activityProof = ctx.computeAppActivity(data) // to compute header - must be after computeOutIdentifier

	txh.Kyber = make([]Signature, len(data.Outputs))
	for i := 0; i < len(data.Inputs); i++ {
		data.Inputs[i].u.UDelta = append(data.Inputs[i].u.UDelta, txh.activityProof...)

		if int(data.Outputs[i].N) != len(data.Inputs[i].u.UDelta)/33 {
			log.Fatal("invalid delta size", data.Outputs[i].Pk[:5], int(data.Outputs[i].N), len(data.Inputs[i].u.UDelta)/33)
		}

		buf.Write(data.Outputs[i].Pk)
		buf.WriteByte(data.Outputs[i].N)
		buf.Write(data.Outputs[i].Data)
		buf.Write(data.Inputs[i].u.UDelta)
		//buf.Write(data.Inputs[i].u.Wmark)

		if ctx.sigContext.SigType == 1 || ctx.sigContext.SigType == 2 {
			ctx.sigContext.unmarshelKeys(&keys, data.Inputs[i].u.Keys)
			txh.Kyber[i] = ctx.sigContext.sign(&keys, buf.Bytes())
		}
		buf.Reset()
	}
	for i := len(data.Inputs); i < len(data.Outputs); i++ {
		data.Outputs[i].u.UDelta = make([]byte, 33)
		copy(data.Outputs[i].u.UDelta, txh.activityProof)

		buf.Write(data.Outputs[i].Pk)
		buf.WriteByte(data.Outputs[i].N)
		buf.Write(data.Outputs[i].Data)
		buf.Write(data.Outputs[i].u.UDelta)
		//buf.Write(data.Outputs[i].u.Wmark)

		if ctx.sigContext.SigType == 1 || ctx.sigContext.SigType == 2 {
			ctx.sigContext.unmarshelKeys(&keys, data.Outputs[i].u.Keys)
			txh.Kyber[i] = ctx.sigContext.sign(&keys, buf.Bytes())
		}
		buf.Reset()
	}
}

func (ctx *ExeContext) verifyAccOrigamiTxHeader(txh *TxHeader, data *AppData) (bool, *string) {
	buf := new(bytes.Buffer)
	var pk Pubkey
	var err string

	// compute header
	for i := 0; i < len(data.Outputs); i++ {
		data.Outputs[i].header = ctx.computeOutIdentifier(data.Outputs[i].Pk, data.Outputs[i].N, data.Outputs[i].Data)
	}

	txh.activityProof = ctx.computeAppActivity(data) // to compute header - must be after computeOutIdentifier

	var bufs [][]byte
	var pks []Pubkey
	if ctx.sigContext.SigType == 2 {
		bufs = make([][]byte, len(data.Outputs))
		pks = make([]Pubkey, len(data.Outputs))
	}
	for i := 0; i < len(data.Inputs); i++ {
		data.Inputs[i].u.UDelta = append(data.Inputs[i].u.UDelta, txh.activityProof...)
		if int(data.Outputs[i].N) != len(data.Inputs[i].u.UDelta)/33 {
			log.Fatal("invalid delta size", data.Outputs[i].Pk[:5], int(data.Outputs[i].N), len(data.Inputs[i].u.UDelta)/33)
		}

		buf.Write(data.Outputs[i].Pk)
		buf.WriteByte(data.Outputs[i].N)
		buf.Write(data.Outputs[i].Data)
		buf.Write(data.Inputs[i].u.UDelta)

		if ctx.sigContext.SigType == 1 {
			ctx.sigContext.unmarshelPublicKeysFromBytes(&pk, data.Inputs[i].u.Keys[:ctx.sigContext.PkSize])
			if ctx.sigContext.verify(&pk, buf.Bytes(), txh.Kyber[i]) == false {
				err = "invalid sig"
				return false, &err
			}
		}
		if ctx.sigContext.SigType == 2 {
			ctx.sigContext.unmarshelPublicKeysFromBytes(&pks[i], data.Inputs[i].u.Keys[:ctx.sigContext.PkSize])
			bufs[i] = make([]byte, buf.Len())
			copy(bufs[i], buf.Bytes())
		}
		buf.Reset()
	}

	for i := len(data.Inputs); i < len(data.Outputs); i++ {
		data.Outputs[i].u.UDelta = make([]byte, 33)
		copy(data.Outputs[i].u.UDelta, txh.activityProof)

		buf.Write(data.Outputs[i].Pk)
		buf.WriteByte(data.Outputs[i].N)
		buf.Write(data.Outputs[i].Data)
		buf.Write(data.Outputs[i].u.UDelta)

		if ctx.sigContext.SigType == 1 {
			ctx.sigContext.unmarshelPublicKeysFromBytes(&pk, data.Outputs[i].Pk)
			if ctx.sigContext.verify(&pk, buf.Bytes(), txh.Kyber[i]) == false {
				err = "invalid sig"
				return false, &err
			}
		}
		if ctx.sigContext.SigType == 2 {
			ctx.sigContext.unmarshelPublicKeysFromBytes(&pks[i], data.Outputs[i].Pk)
			bufs[i] = make([]byte, buf.Len())
			copy(bufs[i], buf.Bytes())
		}
		buf.Reset()
	}
	if ctx.sigContext.SigType == 2 {
		sig := ctx.sigContext.aggregateSignatures(txh.Kyber)
		if !ctx.sigContext.batchVerifyMultipleMsg(pks, bufs, sig) {
			err = "invalid aggregate sig"
			return false, &err
		}
	}
	return true, nil
}
