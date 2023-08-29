package txhelper

import (
	"bytes"
	"errors"
	"log"
)

// PrepareBlockAppDataPeer get output details for inputs using the header
func (ctx *ExeContext) PrepareBlockAppDataPeer(txs []Transaction) (bool, error) {
	i := 0
	used := -1
	found := false
	var err error
	extra := 0

	for t := 0; t < len(txs); t++ {
		// arrange inputs
		for i = 0; i < len(txs[t].Data.Inputs); i++ {
			found, txs[t].Data.Inputs[i].u.id, used, err = ctx.getPeerOut(txs[t].Data.Inputs[i].Header, &txs[t].Data.Inputs[i].u)
			if used == 1 {
				return false, errors.New("TXHELPER_REUSED_IN" + err.Error())
			}
			if found == false {
				// check if they were created in the current block
				for j := 0; j < t; j++ {
					if bytes.Equal(txs[t].Data.Inputs[i].Header, txs[t].Data.Outputs[j].u.H) {
						txs[t].Data.Inputs[i].u.Keys = make([]byte, ctx.sigContext.PkSize)
						copy(txs[t].Data.Inputs[i].u.Keys, txs[t].Data.Outputs[j].Pk)
						txs[t].Data.Inputs[i].u.N = txs[t].Data.Outputs[j].N + 1
						txs[t].Data.Inputs[i].u.Data = make([]byte, ctx.payloadSize)
						copy(txs[t].Data.Inputs[i].u.Data, txs[t].Data.Outputs[j].Data)
						found = true
						break
					}
				}
			}
			if !found {
				return false, errors.New("TXHELPER_INVALID_IN" + err.Error())
			}

			// copy public key
			if i < len(txs[t].Data.Inputs) && (ctx.txModel == 2 || ctx.txModel == 4 || ctx.txModel == 6) {
				txs[t].Data.Outputs[i].Pk = make([]byte, ctx.sigContext.PkSize)
				copy(txs[t].Data.Outputs[i].Pk, txs[t].Data.Inputs[i].u.Keys)
				txs[t].Data.Outputs[i].N = txs[t].Data.Inputs[i].u.N + 1
			}
		}

		// compute the header
		for i = 0; i < len(txs[t].Data.Outputs); i++ {
			txs[t].Data.Outputs[i].u.H = ctx.computeOutIdentifier(txs[t].Data.Outputs[i].Pk, txs[t].Data.Outputs[i].N, txs[t].Data.Outputs[i].Data)
		}

		// arrange ids of outputs for txHeader insertion
		if ctx.txModel >= 1 && ctx.txModel <= 4 {
			for i = 0; i < len(txs[t].Data.Outputs); i++ {
				txs[t].Data.Outputs[i].u.id = ctx.CurrentOutputs + i + extra // must save every output with new id
			}
		} else if ctx.txModel == 5 {
			for i = 0; i < len(txs[t].Data.Outputs); i++ {
				txs[t].Data.Outputs[i].u.id = ctx.outputPointer // must save every output with new id even though input ids will be deleted
				ctx.outputPointer++
			}
		} else if ctx.txModel == 6 { // must save every new output pk with new id
			j := 0
			for i = len(txs[t].Data.Inputs); i < len(txs[t].Data.Outputs); i++ {
				txs[t].Data.Outputs[i].u.id = ctx.CurrentUsers + j // must save every new pk (user) with new id
				j++
			}
		} else {
			log.Fatal("unknown txModel:", ctx.txModel)
		}
	}

	return true, nil
}
