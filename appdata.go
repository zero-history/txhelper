package txhelper

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"golang.org/x/crypto/sha3"
	"log"
	rand2 "math/rand"
)

type InputData struct {
	Header []byte `json:"h"` // identifier like a hash
	u      User
}

type OutputData struct {
	Pk     []byte `json:"p"` // public key
	N      uint8  `json:"n"`
	Data   []byte `json:"d"` // new application data
	header []byte // new application header (Origami)
	u      User   // updated user data
}

type AppData struct {
	Inputs  []InputData  `json:"i"` // inputs as a byte array
	Outputs []OutputData `json:"o"` // outputs as a byte array
}

// computeOutIdentifier computes an unique identifer for each output via hashing
func (ctx *ExeContext) computeOutIdentifier(pk []byte, n uint8, data []byte) []byte {
	hasher := sha3.New256()
	nByte := make([]byte, 1)
	nByte[0] = n
	hasher.Write(pk)
	hasher.Write(nByte)
	hasher.Write(data)

	return hasher.Sum(nil)
}

// RandomAppData creates an application data change for randomly chosen users
func (ctx *ExeContext) RandomAppData(data *AppData, inSize uint8, outSize uint8, averageSize uint16) {
	switch ctx.txModel {
	case 1:
		ctx.utxoAppData(data, inSize, outSize, averageSize)
	case 2:
		ctx.accAppData(data, inSize, outSize, averageSize)
	case 3:
		ctx.utxoAppData(data, inSize, outSize, averageSize)
	case 4:
		ctx.accAppData(data, inSize, outSize, averageSize)
	case 5:
		ctx.utxoAppData(data, inSize, outSize, averageSize)
	case 6:
		ctx.accAppData(data, inSize, outSize, averageSize)
	default:
		log.Fatal("unknown txModel")
	}
}

// PrepareAppDataClient get user details for inputs using the header
func (ctx *ExeContext) PrepareAppDataClient(data *AppData) (bool, error) {
	i := 0

	// arrange inputs
	for i = 0; i < len(data.Inputs); i++ {
		ok, err := ctx.getClientOutFromH(data.Inputs[i].Header, &data.Inputs[i].u)
		if !ok {
			fmt.Println("could not find h:", data.Inputs[i].Header)
			return false, err
		}

		// copy public key
		if i < len(data.Inputs) && (ctx.txModel == 2 || ctx.txModel == 4 || ctx.txModel == 6) {
			data.Outputs[i].Pk = make([]byte, ctx.sigContext.PkSize)
			copy(data.Outputs[i].Pk, data.Inputs[i].u.Keys)
			data.Outputs[i].N = data.Inputs[i].u.N + 1
		}
	}
	for i = 0; i < len(data.Outputs); i++ {
		//update client db with new data
		data.Outputs[i].u.H = ctx.computeOutIdentifier(data.Outputs[i].Pk, data.Outputs[i].N, data.Outputs[i].Data)
	}
	return true, nil
}

// PrepareAppDataPeer get output details for inputs using the header
func (ctx *ExeContext) PrepareAppDataPeer(data *AppData) (bool, error) {
	i := 0
	used := -1
	found := false
	var err error
	// arrange inputs
	for i = 0; i < len(data.Inputs); i++ {
		found, data.Inputs[i].u.id, used, err = ctx.getPeerOut(data.Inputs[i].Header, &data.Inputs[i].u)
		if found == false {
			return false, err
		}
		if used != 0 {
			return false, errors.New("TXHELPER_REUSED_IN" + err.Error())
		}

		// copy public key
		if i < len(data.Inputs) && (ctx.txModel == 2 || ctx.txModel == 4 || ctx.txModel == 6) {
			data.Outputs[i].Pk = make([]byte, ctx.sigContext.PkSize)
			copy(data.Outputs[i].Pk, data.Inputs[i].u.Keys)
			data.Outputs[i].N = data.Inputs[i].u.N + 1
		}
	}

	// arrange ids of outputs for txHeader insertion
	if ctx.txModel >= 1 && ctx.txModel <= 4 {
		for i = 0; i < len(data.Outputs); i++ {
			data.Outputs[i].u.id = ctx.CurrentOutputs + i // must save every output with new id
		}
	} else if ctx.txModel == 5 {
		for i = 0; i < len(data.Outputs); i++ {
			data.Outputs[i].u.id = ctx.outputPointer // must save every output with new id even though input ids will be deleted
			ctx.outputPointer++
		}
	} else if ctx.txModel == 6 { // must save every new output pk with new id
		j := 0
		for i = len(data.Inputs); i < len(data.Outputs); i++ {
			data.Outputs[i].u.id = ctx.CurrentUsers + j // must save every new pk (user) with new id
			j++
		}
	} else {
		log.Fatal("unknown txModel:", ctx.txModel)
	}

	return true, nil
}

// UpdateAppDataClient update user details for new app data changes
func (ctx *ExeContext) UpdateAppDataClient(data *AppData) (bool, error) {
	i := 0

	// utxo
	if ctx.txModel == 1 || ctx.txModel == 3 || ctx.txModel == 5 {
		// save outputs
		for i = 0; i < len(data.Outputs); i++ {
			//update client db with new data
			ok, err := ctx.updateClientOut(data.Outputs[i].u.id, &data.Outputs[i].u)
			if !ok {
				return false, err
			}
		}
	}
	// account
	if ctx.txModel == 2 || ctx.txModel == 4 || ctx.txModel == 6 {
		// save outputs
		for i = 0; i < len(data.Inputs); i++ {
			data.Inputs[i].u.N = data.Outputs[i].N
			data.Inputs[i].u.H = ctx.computeOutIdentifier(data.Outputs[i].Pk, data.Outputs[i].N, data.Outputs[i].Data)
			ok, err := ctx.updateClientOut(data.Inputs[i].u.id, &data.Inputs[i].u)
			if !ok {
				return false, err
			}
		}
		for i = len(data.Inputs); i < len(data.Outputs); i++ {
			data.Outputs[i].u.H = ctx.computeOutIdentifier(data.Outputs[i].Pk, data.Outputs[i].N, data.Outputs[i].Data)
			ok, err := ctx.updateClientOut(data.Outputs[i].u.id, &data.Outputs[i].u)
			if !ok {
				return false, err
			}
		}
	}
	return true, nil
}

// UpdateAppDataPeer update output details for new app data changes
func (ctx *ExeContext) UpdateAppDataPeer(txn int, tx *Transaction) (bool, *string) {
	i := 0
	header := make([]byte, sha256.Size)
	var errM string
	// utxo
	if ctx.txModel == 1 || ctx.txModel == 3 {
		for i = 0; i < len(tx.Data.Inputs); i++ {
			ok, err := ctx.updatePeerOut(tx.Data.Inputs[i].u.id, nil, 0, nil, nil, nil, 1) // update "used"
			if !ok {
				errM = "I couldn't find the input. Did you verify the app data?:" + string(rune(tx.Data.Inputs[i].u.id)) + " " + err.Error()
				return false, &errM
			}
		}
		// save outputs
		for i = 0; i < len(tx.Data.Outputs); i++ {
			//update client db with new data
			header = ctx.computeOutIdentifier(tx.Data.Outputs[i].Pk, tx.Data.Outputs[i].N, tx.Data.Outputs[i].Data)
			ok, err := ctx.insertPeerOut(tx.Data.Outputs[i].u.id, header, &tx.Data.Outputs[i], nil)
			if !ok {
				errM = "I couldn't insert the output" + string(rune(tx.Data.Outputs[i].u.id)) + " " + err.Error()
				return false, &errM
			}
		}
		ctx.CurrentOutputs += len(tx.Data.Outputs)
	}
	// account
	if ctx.txModel == 2 || ctx.txModel == 4 {
		// modify inputs' into ``used'' inputs
		for i = 0; i < len(tx.Data.Inputs); i++ {
			if ctx.sigContext.SigType == 1 || ctx.sigContext.SigType == 2 {
				ok, err := ctx.updatePeerOut(tx.Data.Inputs[i].u.id, nil, 0, nil, nil, nil, 1) // update "used"
				if !ok {
					errM = "I couldn't update the input" + string(rune(tx.Data.Inputs[i].u.id)) + " " + err.Error()
					return false, &errM
				}
			} else {
				log.Fatal("unknown sigType:", ctx.sigContext.SigType)
			}
		}
		// save outputs
		for i = 0; i < len(tx.Data.Outputs); i++ {
			header = ctx.computeOutIdentifier(tx.Data.Outputs[i].Pk, tx.Data.Outputs[i].N, tx.Data.Outputs[i].Data)
			ok, err := ctx.insertPeerOut(tx.Data.Outputs[i].u.id, header, &tx.Data.Outputs[i], nil)
			if !ok {
				errM = "I couldn't update the output" + string(rune(tx.Data.Outputs[i].u.id)) + " " + err.Error()
				return false, &errM
			}
		}
		ctx.CurrentUsers += len(tx.Data.Outputs) - len(tx.Data.Inputs) // update the current user size
		ctx.CurrentOutputs += len(tx.Data.Outputs)                     // update the current output number
	} else if ctx.txModel == 5 {
		// delete inputs
		for i = 0; i < len(tx.Data.Inputs); i++ {
			ok, err := ctx.deletePeerOut(tx.Data.Inputs[i].u.id)
			if !ok {
				errM = "couldn't delete the input. Does it exist" + string(rune(tx.Data.Inputs[i].u.id)) + " " + err.Error()
				return false, &errM
			}
		}
		// save outputs
		for i = 0; i < len(tx.Data.Outputs); i++ {
			header = ctx.computeOutIdentifier(tx.Data.Outputs[i].Pk, tx.Data.Outputs[i].N, tx.Data.Outputs[i].Data)
			ok, err := ctx.insertPeerOut(tx.Data.Outputs[i].u.id, header, &tx.Data.Outputs[i], nil)
			if !ok {
				errM = "I couldn't insert the output" + string(rune(tx.Data.Outputs[i].u.id)) + " " + err.Error()
				return false, &errM
			}
		}
		ctx.CurrentOutputs += len(tx.Data.Outputs) - len(tx.Data.Inputs)
		ctx.DeletedOutputs += len(tx.Data.Inputs)
	} else if ctx.txModel == 6 {
		// modify inputs (h, -, data, n, sig) including "used"
		for i = 0; i < len(tx.Data.Inputs); i++ {
			header = ctx.computeOutIdentifier(tx.Data.Outputs[i].Pk, tx.Data.Outputs[i].N, tx.Data.Outputs[i].Data)
			if ctx.sigContext.SigType == 1 || ctx.sigContext.SigType == 2 {
				tx.Data.Inputs[i].u.Txns = append(tx.Data.Inputs[i].u.Txns, txn)
				ok, err := ctx.updatePeerOut(tx.Data.Inputs[i].u.id, header, int(tx.Data.Outputs[i].N), tx.Data.Outputs[i].Data, tx.Txh.Kyber[i], tx.Data.Inputs[i].u.Txns, 0)
				if !ok {
					errM = "I couldn't update the input" + string(rune(tx.Data.Inputs[i].u.id)) + " " + err.Error()
					return false, &errM
				}
			} else {
				log.Fatal("unknown sigType:", ctx.sigContext.SigType)
			}
		}
		// save new outputs
		for i = len(tx.Data.Inputs); i < len(tx.Data.Outputs); i++ {
			header = ctx.computeOutIdentifier(tx.Data.Outputs[i].Pk, tx.Data.Outputs[i].N, tx.Data.Outputs[i].Data)
			tx.Data.Outputs[i].u.Txns = make([]int, 1)
			tx.Data.Outputs[i].u.Txns[0] = txn
			ok, err := ctx.insertPeerOut(tx.Data.Outputs[i].u.id, header, &tx.Data.Outputs[i], tx.Txh.Kyber[i])
			if !ok {
				errM = "I couldn't update the output" + string(rune(tx.Data.Outputs[i].u.id)) + " " + err.Error()
				return false, &errM
			}
		}
		ctx.CurrentUsers += len(tx.Data.Outputs) - len(tx.Data.Inputs)
		ctx.CurrentOutputs += len(tx.Data.Outputs) - len(tx.Data.Inputs)
		ctx.DeletedOutputs += len(tx.Data.Inputs)
	}
	return true, nil
}

// utxoAppData returns a random application update for UTXO-based models
// Users can have more than one output
// We choose input users and output users in round-robin manner
func (ctx *ExeContext) utxoAppData(data *AppData, inSize uint8, outSize uint8, averageSize uint16) {
	i := 0
	dataSize := 0

	// arrange inputs
	// It takes users in round-robin manner according to the pointer.
	data.Inputs = make([]InputData, inSize)
	for i = 0; i < int(inSize); i++ {
		if ctx.outputPointer <= ctx.inputPointer {
			break
		}
		data.Inputs[i].u.id = ctx.inputPointer
		// get user from client db
		ok, err := ctx.getClientOut(data.Inputs[i].u.id, &data.Inputs[i].u)
		if !ok {
			log.Fatal("utxoAppData: could not find user id:", data.Inputs[i].u.id, err) // This should not happen
		}

		data.Inputs[i].Header = make([]byte, len(data.Inputs[i].u.H))
		copy(data.Inputs[i].Header, data.Inputs[i].u.H)
		ctx.inputPointer++
	}
	inSize = uint8(i & 0xff) // update the input size
	data.Inputs = data.Inputs[:inSize]

	// create outputs
	keyBuf := new(bytes.Buffer)
	data.Outputs = make([]OutputData, outSize)
	var jsonBytes []byte
	for i = 0; i < int(outSize); i++ {
		// a new user with new pk can be created or the existing user with new N can be created
		choice := rand2.Int() % 2
		if (choice == 0 || ctx.CurrentUsers >= ctx.TotalUsers) && int(inSize) > i && ctx.txModel != 5 { // use input pk with new n
			jsonBytes, _ = json.Marshal(&data.Inputs[i].u)
			if json.Unmarshal(jsonBytes, &data.Outputs[i].u) != nil {
				log.Fatal("could not copy data")
			}
		} else { // create new user
			var keys SigKeyPair
			ctx.sigContext.generate(&keys)
			ctx.sigContext.marshelKeys(&keys, keyBuf)
			data.Outputs[i].u = User{
				H:      make([]byte, 32),
				N:      0,
				Keys:   keyBuf.Bytes(),
				Data:   make([]byte, ctx.payloadSize),
				UDelta: make([]byte, 0),
			}
			ctx.CurrentUsers++
		}
		data.Outputs[i].u.id = ctx.outputPointer // save for client db
		ok, err := ctx.insertClientOut(ctx.outputPointer, &data.Outputs[i].u)
		if !ok {
			log.Fatal("couldn't insert outputs:", err)
		}
		keyBuf.Reset()
		// compute the header
		ok, err = ctx.getClientOut(data.Outputs[i].u.id, &data.Outputs[i].u)
		if !ok {
			log.Fatal("utxoAppData: could not find user id:", data.Outputs[i].u.id, err) // This should not happen
		}

		// copy the public key
		data.Outputs[i].Pk = make([]byte, ctx.sigContext.PkSize)
		copy(data.Outputs[i].Pk, data.Outputs[i].u.Keys)
		if len(data.Outputs[i].u.Keys) != int(ctx.sigContext.PkSize+ctx.sigContext.SkSize) {
			log.Fatal("invalid pk size")
		}
		// update n
		data.Outputs[i].u.N += 1
		data.Outputs[i].N = data.Outputs[i].u.N
		// get random new data
		dataSize, _ = rand.Read(data.Outputs[i].u.Data)
		if dataSize != int(ctx.payloadSize) {
			log.Fatal("invalid utxo data size")
		}
		data.Outputs[i].Data = make([]byte, averageSize)
		copy(data.Outputs[i].Data, data.Outputs[i].u.Data)
		// update variables
		ctx.outputPointer++
		ctx.CurrentOutputs++
	}
}

// accAppData returns random application updates for account-based models
// All accounts [0, inSize] will be existing accounts and new accounts are in [inSize, OutSize].
// If there are not enough existing accounts, inSize will be updated
func (ctx *ExeContext) accAppData(data *AppData, inSize uint8, outSize uint8, averageSize uint16) {
	i := uint8(0)
	id := 0
	dataSize := 0

	if inSize > outSize {
		inSize = outSize // all inputs should be in outputs
	}

	if ctx.CurrentUsers == 0 {
		inSize = 0
		outSize = ctx.averageInputMax // to avoid overlapping between pk for the 2nd transaction
	} else if ctx.CurrentUsers == ctx.TotalUsers { // should not add more accounts
		if inSize == 0 {
			inSize = 1 // Otherwise, there will be zero input/output transactions
		}
		outSize = inSize
	}
	//inSize = 0

	// arrange inputs and outputs of existing users
	// It takes users in round-robin manner according to the pointer.
	data.Inputs = make([]InputData, inSize)
	data.Outputs = make([]OutputData, outSize)
	id = rand2.Int() % 0xff
	for i = 0; i < inSize; i++ {
		id += 1
		data.Inputs[i].u.id = (id) % ctx.CurrentUsers // save for db
		// get random user from client db
		ok, err := ctx.getClientOut(data.Inputs[i].u.id, &data.Inputs[i].u)
		if !ok {
			log.Fatal("accAppData: could not find user id:", id, inSize, data.Inputs[i].u.id, ctx.CurrentUsers, err)
		}
		// if N = 0 is zero then no previous outputs were created
		if data.Inputs[i].u.N == 0 {
			break
		}
		// copy the header
		data.Inputs[i].Header = make([]byte, len(data.Inputs[i].u.H))
		copy(data.Inputs[i].Header, data.Inputs[i].u.H)
		// copy the public key
		data.Outputs[i].Pk = make([]byte, ctx.sigContext.PkSize)
		copy(data.Outputs[i].Pk, data.Inputs[i].u.Keys)
		if len(data.Inputs[i].u.Keys) != int(ctx.sigContext.PkSize+ctx.sigContext.SkSize) {
			log.Fatal("invalid pk size")
		}
		// update n
		data.Outputs[i].N = data.Inputs[i].u.N + 1
		// get random new data
		dataSize, _ = rand.Read(data.Inputs[i].u.Data)
		if dataSize != int(ctx.payloadSize) {
			log.Fatal("invalid app data size")
		}
		data.Outputs[i].Data = make([]byte, averageSize)
		copy(data.Outputs[i].Data, data.Inputs[i].u.Data)
	}
	inSize = i // update the input size
	data.Inputs = data.Inputs[:inSize]

	// arrange outputs of non-existing users
	// Next outputPointer will be the outputPointer + number of inputs
	keyBuf := new(bytes.Buffer)
	for i = inSize; i < outSize; i++ {
		// create user for the
		var keys SigKeyPair
		ctx.sigContext.generate(&keys)
		ctx.sigContext.marshelKeys(&keys, keyBuf)
		data.Outputs[i].u = User{
			H:      make([]byte, 32),
			N:      0,
			Keys:   keyBuf.Bytes(),
			Data:   make([]byte, ctx.payloadSize),
			UDelta: make([]byte, 0),
		}
		data.Outputs[i].u.id = ctx.CurrentUsers // save for db
		ok, err := ctx.insertClientOut(ctx.CurrentUsers, &data.Outputs[i].u)
		if !ok {
			log.Fatal("couldn't insert outputs:", err)
		}
		ctx.CurrentUsers += 1
		keyBuf.Reset()
		// tests
		ok, err = ctx.getClientOut(data.Outputs[i].u.id, &data.Outputs[i].u)
		if !ok {
			log.Fatal("accAppData: could not find user id:", id, err)
		}

		// copy the public key
		data.Outputs[i].Pk = make([]byte, ctx.sigContext.PkSize)
		copy(data.Outputs[i].Pk, data.Outputs[i].u.Keys)
		if len(data.Outputs[i].u.Keys) != int(ctx.sigContext.PkSize+ctx.sigContext.SkSize) {
			log.Fatal("invalid pk size")
		}
		// update n
		data.Outputs[i].u.N = 1
		data.Outputs[i].N = data.Outputs[i].u.N
		// get random new data
		dataSize, _ = rand.Read(data.Outputs[i].u.Data)
		if dataSize != int(ctx.payloadSize) {
			log.Fatal("invalid app data size")
		}
		data.Outputs[i].Data = make([]byte, averageSize)
		copy(data.Outputs[i].Data, data.Outputs[i].u.Data)
	}
	ctx.outputPointer += int(outSize)
	ctx.outputPointer %= ctx.TotalUsers
}
