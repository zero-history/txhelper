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
	keybuffer := new(bytes.Buffer)
	var keys SigKeyPair
	ctx.sigContext.generate(&keys) // initiating parameters

	for i := 0; i < len(data.Inputs); i++ {
		buffer.Write(data.Inputs[i].Header)
	}
	for i := 0; i < len(data.Outputs); i++ {
		buffer.Write(data.Outputs[i].Pk)
		buffer.WriteByte(data.Outputs[i].N)
		buffer.Write(data.Outputs[i].Data)
	}

	if ctx.sigContext.SigType == 1 || ctx.sigContext.SigType == 2 {
		// if there are no inputs, all output owners must sign
		if len(data.Inputs) == 0 {
			txh.Kyber = make([]Signature, len(data.Outputs))
			for i := 0; i < len(data.Outputs); i++ {
				keybuffer.Write(data.Outputs[i].u.Keys)
				ctx.sigContext.unmarshelKeys(&keys, keybuffer)
				txh.Kyber[i] = ctx.sigContext.sign(&keys, buffer.Bytes())
				keybuffer.Reset()
			}
		} else { // otherwise, only input owners sign
			txh.Kyber = make([]Signature, len(data.Inputs))
			for i := 0; i < len(data.Inputs); i++ {
				keybuffer.Write(data.Inputs[i].u.Keys)
				ctx.sigContext.unmarshelKeys(&keys, keybuffer)
				txh.Kyber[i] = ctx.sigContext.sign(&keys, buffer.Bytes())
				keybuffer.Reset()
			}
		}
	}
}

func (ctx *ExeContext) verifyUtxoClassicTxHeader(txh *TxHeader, data *AppData) (bool, *string) {
	buffer := new(bytes.Buffer)
	keybuffer := new(bytes.Buffer)
	var pk Pubkey
	var keys SigKeyPair
	var err string
	ctx.sigContext.getPubKey(&keys) // initiating parameters

	for i := 0; i < len(data.Inputs); i++ {
		buffer.Write(data.Inputs[i].Header)
	}
	for i := 0; i < len(data.Outputs); i++ {
		buffer.Write(data.Outputs[i].Pk)
		buffer.WriteByte(data.Outputs[i].N)
		buffer.Write(data.Outputs[i].Data)
	}

	if ctx.sigContext.SigType == 1 || ctx.sigContext.SigType == 2 {
		if len(data.Outputs) == 0 {
			for i := 0; i < len(data.Outputs); i++ {
				keybuffer.Write(data.Outputs[i].Pk)
				ctx.sigContext.unmarshelPublicKeys(&pk, keybuffer)
				if ctx.sigContext.verify(&pk, buffer.Bytes(), txh.Kyber[i]) == false {
					err = "invalid sig"
					return false, &err
				}
				keybuffer.Reset()
			}
		} else {
			for i := 0; i < len(data.Inputs); i++ {
				keybuffer.Write(data.Inputs[i].u.Keys)
				ctx.sigContext.unmarshelPublicKeys(&pk, keybuffer)
				if ctx.sigContext.verify(&pk, buffer.Bytes(), txh.Kyber[i]) == false {
					err = "invalid sig"
					return false, &err
				}
				keybuffer.Reset()
			}
		}
	}

	return true, nil
}

func (ctx *ExeContext) accClassicTxHeader(txh *TxHeader, data *AppData) {
	buffer := new(bytes.Buffer)
	keybuffer := new(bytes.Buffer)
	var keys SigKeyPair
	ctx.sigContext.generate(&keys) // initiating parameters

	for i := 0; i < len(data.Inputs); i++ {
		buffer.Write(data.Inputs[i].Header)
	}
	for i := 0; i < len(data.Outputs); i++ {
		buffer.Write(data.Outputs[i].Pk)
		buffer.WriteByte(byte(data.Outputs[i].N))
		buffer.Write(data.Outputs[i].Data)
	}

	if ctx.sigContext.SigType == 1 || ctx.sigContext.SigType == 2 {
		if len(data.Inputs) == 0 { // output owners must sign if there are no inputs
			txh.Kyber = make([]Signature, len(data.Outputs))
			for i := 0; i < len(data.Outputs); i++ {
				keybuffer.Write(data.Outputs[i].u.Keys)
				ctx.sigContext.unmarshelKeys(&keys, keybuffer)
				txh.Kyber[i] = ctx.sigContext.sign(&keys, buffer.Bytes())
				keybuffer.Reset()
			}
		} else { // Otherwise, only input owners sign
			txh.Kyber = make([]Signature, len(data.Inputs))
			for i := 0; i < len(data.Inputs); i++ {
				keybuffer.Write(data.Inputs[i].u.Keys)
				ctx.sigContext.unmarshelKeys(&keys, keybuffer)
				txh.Kyber[i] = ctx.sigContext.sign(&keys, buffer.Bytes())
				keybuffer.Reset()
			}
		}
	}
}

func (ctx *ExeContext) verifyAccClassicTxHeader(txh *TxHeader, data *AppData) (bool, *string) {
	buffer := new(bytes.Buffer)
	keybuffer := new(bytes.Buffer)
	var pk Pubkey
	var keys SigKeyPair
	var err string
	ctx.sigContext.getPubKey(&keys) // initiating parameters

	for i := 0; i < len(data.Inputs); i++ {
		buffer.Write(data.Inputs[i].Header)
	}
	for i := 0; i < len(data.Outputs); i++ {
		buffer.Write(data.Outputs[i].Pk)
		buffer.WriteByte(data.Outputs[i].N)
		buffer.Write(data.Outputs[i].Data)
	}

	if ctx.sigContext.SigType == 1 || ctx.sigContext.SigType == 2 {
		if len(data.Inputs) == 0 {
			for i := 0; i < len(data.Outputs); i++ {
				keybuffer.Write(data.Outputs[i].Pk)
				ctx.sigContext.unmarshelPublicKeys(&pk, keybuffer)
				if ctx.sigContext.verify(&pk, buffer.Bytes(), txh.Kyber[i]) == false {
					err = "invalid sig"
					return false, &err
				}
				keybuffer.Reset()
			}

		} else {
			for i := 0; i < len(data.Inputs); i++ {
				keybuffer.Write(data.Inputs[i].u.Keys)
				ctx.sigContext.unmarshelPublicKeys(&pk, keybuffer)
				if ctx.sigContext.verify(&pk, buffer.Bytes(), txh.Kyber[i]) == false {
					err = "invalid sig"
					return false, &err
				}
				keybuffer.Reset()
			}
		}
	}
	return true, nil
}

func (ctx *ExeContext) utxoAccountableClassicTxHeader(txh *TxHeader, data *AppData) {
	buffer := new(bytes.Buffer)
	keybuffer := new(bytes.Buffer)
	var keys SigKeyPair
	var sig Signature
	ctx.sigContext.generate(&keys) // initiating parameters

	for i := 0; i < len(data.Inputs); i++ {
		buffer.Write(data.Inputs[i].Header)
	}
	for i := 0; i < len(data.Outputs); i++ {
		buffer.Write(data.Outputs[i].Pk)
		buffer.WriteByte(data.Outputs[i].N)
		buffer.Write(data.Outputs[i].Data)
	}

	txh.Kyber = make([]Signature, len(data.Inputs))
	for i := 0; i < len(data.Inputs); i++ {
		if ctx.sigContext.SigType == 1 || ctx.sigContext.SigType == 2 {
			keybuffer.Write(data.Inputs[i].u.Keys)
			ctx.sigContext.unmarshelKeys(&keys, keybuffer)
			txh.Kyber[i] = ctx.sigContext.sign(&keys, buffer.Bytes())
			keybuffer.Reset()
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
				keybuffer.Write(data.Outputs[i].u.Keys)
				ctx.sigContext.unmarshelKeys(&keys, keybuffer)
				sig = ctx.sigContext.sign(&keys, buffer.Bytes())
				keybuffer.Reset()
				txh.Kyber = append(txh.Kyber, sig)
			}
		}
	}
}

func (ctx *ExeContext) verifyUtxoAccountableClassicTxHeader(txh *TxHeader, data *AppData) (bool, *string) {
	buffer := new(bytes.Buffer)
	keybuffer := new(bytes.Buffer)
	var pk Pubkey
	var keys SigKeyPair
	var err string
	ctx.sigContext.getPubKey(&keys) // initiating parameters

	for i := 0; i < len(data.Inputs); i++ {
		buffer.Write(data.Inputs[i].Header)
	}
	for i := 0; i < len(data.Outputs); i++ {
		buffer.Write(data.Outputs[i].Pk)
		buffer.WriteByte(data.Outputs[i].N)
		buffer.Write(data.Outputs[i].Data)
	}

	for i := 0; i < len(data.Inputs); i++ {
		if ctx.sigContext.SigType == 1 || ctx.sigContext.SigType == 2 {
			keybuffer.Write(data.Inputs[i].u.Keys)
			ctx.sigContext.unmarshelPublicKeys(&pk, keybuffer)
			if ctx.sigContext.verify(&pk, buffer.Bytes(), txh.Kyber[i]) == false {
				err = "invalid sig"
				return false, &err
			}
			keybuffer.Reset()
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
				keybuffer.Write(data.Outputs[i].Pk)
				ctx.sigContext.unmarshelPublicKeys(&pk, keybuffer)
				if ctx.sigContext.verify(&pk, buffer.Bytes(), txh.Kyber[j+len(data.Inputs)]) == false {
					err = "invalid sig"
					return false, &err
				}
				keybuffer.Reset()
				j++
			}
		}
	}
	return true, nil
}

func (ctx *ExeContext) accAccountableClassicTxHeader(txh *TxHeader, data *AppData) {
	buffer := new(bytes.Buffer)
	keybuffer := new(bytes.Buffer)
	var keys SigKeyPair
	ctx.sigContext.generate(&keys) // initiating parameters

	for i := 0; i < len(data.Inputs); i++ {
		buffer.Write(data.Inputs[i].Header)
	}
	for i := 0; i < len(data.Outputs); i++ {
		buffer.Write(data.Outputs[i].Pk)
		buffer.WriteByte(data.Outputs[i].N)
		buffer.Write(data.Outputs[i].Data)
	}

	txh.Kyber = make([]Signature, len(data.Outputs))
	for i := 0; i < len(data.Inputs); i++ {
		if ctx.sigContext.SigType == 1 || ctx.sigContext.SigType == 2 {
			keybuffer.Write(data.Inputs[i].u.Keys)
			ctx.sigContext.unmarshelKeys(&keys, keybuffer)
			txh.Kyber[i] = ctx.sigContext.sign(&keys, buffer.Bytes())
			keybuffer.Reset()
		}
	}
	for i := len(data.Inputs); i < len(data.Outputs); i++ {
		if ctx.sigContext.SigType == 1 || ctx.sigContext.SigType == 2 {
			keybuffer.Write(data.Outputs[i].u.Keys)
			ctx.sigContext.unmarshelKeys(&keys, keybuffer)
			txh.Kyber[i] = ctx.sigContext.sign(&keys, buffer.Bytes())
			keybuffer.Reset()
		}
	}
}

func (ctx *ExeContext) verifyAccAccountableClassicTxHeader(txh *TxHeader, data *AppData) (bool, *string) {
	buffer := new(bytes.Buffer)
	keybuffer := new(bytes.Buffer)
	var pk Pubkey
	var keys SigKeyPair
	var err string
	ctx.sigContext.getPubKey(&keys) // initiating parameters

	for i := 0; i < len(data.Inputs); i++ {
		buffer.Write(data.Inputs[i].Header)
	}
	for i := 0; i < len(data.Outputs); i++ {
		buffer.Write(data.Outputs[i].Pk)
		buffer.WriteByte(data.Outputs[i].N)
		buffer.Write(data.Outputs[i].Data)
	}

	for i := 0; i < len(data.Inputs); i++ {
		if ctx.sigContext.SigType == 1 || ctx.sigContext.SigType == 2 {
			keybuffer.Write(data.Inputs[i].u.Keys)
			ctx.sigContext.unmarshelPublicKeys(&pk, keybuffer)
			if ctx.sigContext.verify(&pk, buffer.Bytes(), txh.Kyber[i]) == false {
				err = "invalid sig"
				return false, &err
			}
			keybuffer.Reset()
		}
	}
	for i := len(data.Inputs); i < len(data.Outputs); i++ {
		if ctx.sigContext.SigType == 1 || ctx.sigContext.SigType == 2 {
			keybuffer.Write(data.Outputs[i].Pk)
			ctx.sigContext.unmarshelPublicKeys(&pk, keybuffer)
			if ctx.sigContext.verify(&pk, buffer.Bytes(), txh.Kyber[i]) == false {
				err = "invalid sig"
				return false, &err
			}
			keybuffer.Reset()
		}
	}
	return true, nil
}

func (ctx *ExeContext) utxoOrigamiTxHeader(txh *TxHeader, data *AppData) {
	buffer := new(bytes.Buffer)
	keybuffer := new(bytes.Buffer)

	negkeysP := make([]*SigKeyPair, len(data.Inputs))
	keysP := make([]*SigKeyPair, len(data.Outputs))
	negkeys := make([]SigKeyPair, len(data.Inputs))
	pluskeys := make([]SigKeyPair, len(data.Outputs))

	// create keys
	for i := 0; i < len(data.Inputs); i++ {
		keybuffer.Write(data.Inputs[i].u.Keys)
		ctx.sigContext.generate(&negkeys[i])
		ctx.sigContext.unmarshelKeys(&negkeys[i], keybuffer)
		keybuffer.Reset()
		negkeysP[i] = &negkeys[i]
	}
	// compute header
	for i := 0; i < len(data.Outputs); i++ {
		keybuffer.Write(data.Outputs[i].u.Keys)
		ctx.sigContext.generate(&pluskeys[i])
		ctx.sigContext.unmarshelKeys(&pluskeys[i], keybuffer)
		keybuffer.Reset()
		keysP[i] = &pluskeys[i]
		data.Outputs[i].header = ctx.computeOutIdentifier(data.Outputs[i].Pk, data.Outputs[i].N, data.Outputs[i].Data)
	}
	txh.activityProof = ctx.computeAppActivity(data) // to compute header - must be after computeOutIdentifier
	txh.excessPK = ctx.sigContext.diffPKFromPairs(keysP, negkeysP)

	txh.Kyber = make([]Signature, 1)

	if len(txh.activityProof) != 33 {
		log.Fatal("error in activities")
	}

	keybuffer.Reset()
	keybuffer.Write(txh.excessPK)
	var pk Pubkey
	var keys SigKeyPair
	ctx.sigContext.generate(&keys)
	pk = ctx.sigContext.getPubKey(&keys)
	ctx.sigContext.unmarshelPublicKeys(&pk, keybuffer)

	buffer.Write(txh.activityProof)
	buffer.Write(txh.excessPK)
	txh.Kyber[0] = ctx.sigContext.diffSign(keysP, negkeysP, &pk, buffer.Bytes())
}

func (ctx *ExeContext) verifyUtxoOrigamiTxHeader(txh *TxHeader, data *AppData) (bool, *string) {
	buffer := new(bytes.Buffer)
	keybuffer := new(bytes.Buffer)
	var keys SigKeyPair
	ctx.sigContext.generate(&keys)

	negkeysP := make([]*Pubkey, len(data.Inputs))
	keysP := make([]*Pubkey, len(data.Outputs))
	negkeys := make([]Pubkey, len(data.Inputs))
	pluskeys := make([]Pubkey, len(data.Outputs))

	// create keys
	for i := 0; i < len(data.Inputs); i++ {
		keybuffer.Write(data.Inputs[i].u.Keys)
		negkeys[i] = ctx.sigContext.getPubKey(&keys)
		ctx.sigContext.unmarshelPublicKeys(&negkeys[i], keybuffer)
		keybuffer.Reset()
		negkeysP[i] = &negkeys[i]
	}
	// compute header
	for i := 0; i < len(data.Outputs); i++ {
		keybuffer.Write(data.Outputs[i].Pk)
		pluskeys[i] = ctx.sigContext.getPubKey(&keys)
		ctx.sigContext.unmarshelPublicKeys(&pluskeys[i], keybuffer)
		keybuffer.Reset()
		keysP[i] = &pluskeys[i]
		data.Outputs[i].header = ctx.computeOutIdentifier(data.Outputs[i].Pk, data.Outputs[i].N, data.Outputs[i].Data)
	}
	txh.activityProof = ctx.computeAppActivity(data) // to compute header - must be after computeOutIdentifier
	txh.excessPK = ctx.sigContext.diffPK(keysP, negkeysP)

	buffer.Write(txh.activityProof)
	buffer.Write(txh.excessPK)

	keybuffer.Reset()
	keybuffer.Write(txh.excessPK)
	var pk Pubkey
	pk = ctx.sigContext.getPubKey(&keys)
	ctx.sigContext.unmarshelPublicKeys(&pk, keybuffer)
	if !ctx.sigContext.verify(&pk, buffer.Bytes(), txh.Kyber[0]) {
		err := "invalid sig"
		return false, &err
	}

	return true, nil
}

func (ctx *ExeContext) accOrigamiTxHeader(txh *TxHeader, data *AppData) {
	buf := new(bytes.Buffer)
	keybuffer := new(bytes.Buffer)
	var keys SigKeyPair
	ctx.sigContext.generate(&keys) // initiating parameters

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
			keybuffer.Write(data.Inputs[i].u.Keys)
			ctx.sigContext.unmarshelKeys(&keys, keybuffer)
			txh.Kyber[i] = ctx.sigContext.sign(&keys, buf.Bytes())
			keybuffer.Reset()
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
			keybuffer.Write(data.Outputs[i].u.Keys)
			ctx.sigContext.unmarshelKeys(&keys, keybuffer)
			txh.Kyber[i] = ctx.sigContext.sign(&keys, buf.Bytes())
			keybuffer.Reset()
		}
		buf.Reset()
	}
}

func (ctx *ExeContext) verifyAccOrigamiTxHeader(txh *TxHeader, data *AppData) (bool, *string) {
	buf := new(bytes.Buffer)
	keybuffer := new(bytes.Buffer)
	var pk Pubkey
	var keys SigKeyPair
	var err string
	ctx.sigContext.getPubKey(&keys) // initiating parameters

	// compute header
	for i := 0; i < len(data.Outputs); i++ {
		data.Outputs[i].header = ctx.computeOutIdentifier(data.Outputs[i].Pk, data.Outputs[i].N, data.Outputs[i].Data)
	}

	txh.activityProof = ctx.computeAppActivity(data) // to compute header - must be after computeOutIdentifier

	for i := 0; i < len(data.Inputs); i++ {
		data.Inputs[i].u.UDelta = append(data.Inputs[i].u.UDelta, txh.activityProof...)
		if int(data.Outputs[i].N) != len(data.Inputs[i].u.UDelta)/33 {
			log.Fatal("invalid delta size", data.Outputs[i].Pk[:5], int(data.Outputs[i].N), len(data.Inputs[i].u.UDelta)/33)
		}

		buf.Write(data.Outputs[i].Pk)
		buf.WriteByte(data.Outputs[i].N)
		buf.Write(data.Outputs[i].Data)
		buf.Write(data.Inputs[i].u.UDelta)

		if ctx.sigContext.SigType == 1 || ctx.sigContext.SigType == 2 {
			keybuffer.Write(data.Inputs[i].u.Keys)
			ctx.sigContext.unmarshelPublicKeys(&pk, keybuffer)
			if ctx.sigContext.verify(&pk, buf.Bytes(), txh.Kyber[i]) == false {
				err = "invalid sig"
				return false, &err
			}
			keybuffer.Reset()
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

		//fmt.Println("sig ", data.Outputs[i].u.id, buf.Bytes())
		if ctx.sigContext.SigType == 1 || ctx.sigContext.SigType == 2 {
			keybuffer.Write(data.Outputs[i].Pk)
			ctx.sigContext.unmarshelPublicKeys(&pk, keybuffer)
			if ctx.sigContext.verify(&pk, buf.Bytes(), txh.Kyber[i]) == false {
				err = "invalid sig"
				return false, &err
			}
			keybuffer.Reset()
		}
		buf.Reset()
	}
	return true, nil
}
