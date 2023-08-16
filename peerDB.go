package txhelper

import "C"
import (
	"bytes"
	"database/sql"
	"errors"
	_ "github.com/mattn/go-sqlite3"
	"log"
	"strconv"
	"unsafe"
)

// #cgo CFLAGS: -g -Wall
// #cgo LDFLAGS: -lcrypto
// #include <stdlib.h>
// #include <stdint.h>
// #include <openssl/bn.h>
import "C"

func inttoByte4(a int, bytes []byte) {
	bytes[0] = uint8(a & 0xff)
	bytes[1] = uint8((a >> 8) & 0xff)
	bytes[2] = uint8((a >> 16) & 0xff)
	bytes[3] = uint8((a >> 24) & 0xff)
}

func byte4toInt(bytes []byte) (a int) {
	a = int(bytes[0]) | (int(bytes[1]) << 8) | (int(bytes[2]) << 16) | (int(bytes[3]) << 24)
	return a
}

func (ctx *ExeContext) initPeerDB() {
	var err error

	ctx.db, err = sql.Open("sqlite3", "peer"+strconv.FormatInt(int64(ctx.exeId), 10)+".db")
	if err != nil {
		log.Fatal(err)
	}

	if ctx.txModel >= 1 && ctx.txModel <= 4 {
		// used - 0 (not used for inputs), 1 (used once), if used > 1 is invalid (used for verification)
		statement := "DROP TABLE IF EXISTS outputs; " +
			"CREATE TABLE outputs(id INTEGER PRIMARY KEY AUTOINCREMENT, h BLOB UNIQUE, pk BLOB, n INTEGER, Data BLOB, used INTEGER);"
		_, err = ctx.db.Exec(statement)
		if err != nil {
			log.Fatal(err)
		}
		// allInIds - stores an int array of input ids
		// allOutIds - stores an int array of allOutIds ids
		statement = "DROP TABLE IF EXISTS txHeaders; " +
			"CREATE TABLE txHeaders(txn INTEGER PRIMARY KEY AUTOINCREMENT, sigAll BLOB, allInIds BLOB, allOutIds BLOB);"
		_, err = ctx.db.Exec(statement)
		if err != nil {
			log.Fatal(err)
		}
		// create an index table for h
		statement = "DROP TABLE IF EXISTS outputs_index; " +
			"CREATE UNIQUE INDEX outputs_index ON outputs (h ASC);"
		_, err = ctx.db.Exec(statement)
		if err != nil {
			log.Fatal(err)
		}
		if ctx.txModel == 2 || ctx.txModel == 4 {
			// create an index table for pk
			statement = "DROP INDEX IF EXISTS outputs_index2; " +
				"CREATE INDEX outputs_index2 ON outputs (pk ASC);"
			_, err = ctx.db.Exec(statement)
			if err != nil {
				log.Fatal(err)
			}
		}
	} else if ctx.txModel == 5 {
		statement := "DROP TABLE IF EXISTS outputs; " +
			"CREATE TABLE outputs(id INTEGER PRIMARY KEY AUTOINCREMENT, h BLOB UNIQUE, pk BLOB, n INTEGER, Data BLOB, used INTEGER);"
		_, err = ctx.db.Exec(statement)
		if err != nil {
			log.Fatal(err)
		}
		statement = "DROP TABLE IF EXISTS txHeaders; " +
			"CREATE TABLE txHeaders(txn INTEGER PRIMARY KEY AUTOINCREMENT, activity BLOB, excess BLOB, sig BLOB);"
		_, err = ctx.db.Exec(statement)
		if err != nil {
			log.Fatal(err)
		}
		// create an index table for h
		statement = "DROP INDEX IF EXISTS outputs_index; " +
			"CREATE UNIQUE INDEX outputs_index ON outputs (h ASC);"
		_, err = ctx.db.Exec(statement)
		if err != nil {
			log.Fatal(err)
		}
		// create an index table for pk
		statement = "DROP INDEX IF EXISTS outputs_index2; " +
			"CREATE UNIQUE INDEX outputs_index2 ON outputs (pk ASC);"
		_, err = ctx.db.Exec(statement)
		if err != nil {
			log.Fatal(err)
		}
	} else if ctx.txModel == 6 {
		// used - 0 (not used for inputs), 1 (used once), if used > 1 is invalid (used for verification)
		statement := "DROP TABLE IF EXISTS outputs; " +
			"CREATE TABLE outputs(id INTEGER PRIMARY KEY AUTOINCREMENT, h BLOB UNIQUE, pk BLOB UNIQUE, n INTEGER, Data BLOB, sig BLOB, Txns BLOB, used INTEGER);"
		_, err = ctx.db.Exec(statement)
		if err != nil {
			log.Fatal(err)
		}
		// allInIds - stores an int array of input ids
		// allOutIds - stores an int array of allOutIds ids
		statement = "DROP TABLE IF EXISTS txHeaders; " +
			"CREATE TABLE txHeaders(txn INTEGER PRIMARY KEY AUTOINCREMENT, activity BLOB, allOutIds BLOB);"
		_, err = ctx.db.Exec(statement)
		if err != nil {
			log.Fatal(err)
		}
		// create an index table for h
		statement = "DROP INDEX IF EXISTS outputs_index; " +
			"CREATE UNIQUE INDEX outputs_index ON outputs (h ASC);"
		_, err = ctx.db.Exec(statement)
		if err != nil {
			log.Fatal(err)
		}
		// create an index table for pk
		statement = "DROP INDEX IF EXISTS outputs_index2; " +
			"CREATE UNIQUE INDEX outputs_index2 ON outputs (pk ASC);"
		_, err = ctx.db.Exec(statement)
		if err != nil {
			log.Fatal(err)
		}
	}
}

// insertPeerOut enter an outputdata. For Origami, give txn as well.
func (ctx *ExeContext) insertPeerOut(id int, h []byte, out *OutputData, sig []byte) (bool, error) {

	if ctx.txModel >= 1 && ctx.txModel <= 5 {
		stm, err := ctx.db.Prepare("INSERT INTO outputs(id, h, pk, n, Data, used) VALUES(?, ?, ?, ?, ?, ?);")
		if err != nil {
			return false, err
		}
		defer stm.Close()
		_, err = stm.Exec(id, h, out.Pk, out.N, out.Data, 0)
		if err != nil {
			return false, err
		}
	} else if ctx.txModel == 6 {
		txnBytes := make([]byte, len(out.u.Txns)*4)
		for i := 0; i < len(out.u.Txns); i++ {
			inttoByte4(out.u.Txns[i], txnBytes[i*4:])
		}
		stm, err := ctx.db.Prepare("INSERT INTO outputs(id, h, pk, n, Data, sig, Txns, used) VALUES(?, ?, ?, ?, ?, ?, ?, ?);")
		if err != nil {
			return false, err
		}
		defer stm.Close()
		_, err = stm.Exec(id, h, out.Pk, out.N, out.Data, sig, txnBytes, 0)
		if err != nil {
			return false, err
		}
	}
	return true, nil
}

// deletePeerOut deletes an output from id
func (ctx *ExeContext) deletePeerOut(id int) (bool, error) {

	stm, err := ctx.db.Prepare("DELETE FROM outputs WHERE id = ?;")
	if err != nil {
		return false, err
	}
	defer stm.Close()
	_, err = stm.Exec(id)
	if err != nil {
		return false, err
	}
	return true, nil
}

// updatePeerOut only updates used in (1-4). for 6: updates " n = ?, data = ?, sig = ?, used = ?"
func (ctx *ExeContext) updatePeerOut(id int, h []byte, n int, data []byte, sig []byte, txns []int, used int) (bool, error) {

	if ctx.txModel >= 1 && ctx.txModel <= 4 {
		stm, err := ctx.db.Prepare("UPDATE outputs SET used = used + ? WHERE id = ?;")
		if err != nil {
			return false, err
		}
		defer stm.Close()
		_, err = stm.Exec(used, id)
		if err != nil {
			return false, err
		}

	} else if ctx.txModel == 5 {
		log.Fatal("no need")
	} else if ctx.txModel == 6 {
		txnBytes := make([]byte, len(txns)*4)
		for i := 0; i < len(txns); i++ {
			inttoByte4(txns[i], txnBytes[i*4:])
		}
		stm, err := ctx.db.Prepare("UPDATE outputs SET h = ?, n = ?, data = ?, sig = ?, Txns = ?, used = ? WHERE id = ?;")
		if err != nil {
			return false, err
		}
		defer stm.Close()
		_, err = stm.Exec(h, n, data, sig, txnBytes, used, id)
		if err != nil {
			return false, err
		}
	}
	return true, nil
}

func (ctx *ExeContext) usedPeerOutHeader(h []byte) (bool, int) {
	var err error
	id := 0

	row := ctx.db.QueryRow("SELECT id  FROM outputs WHERE h = ?;", h)
	err = row.Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return false, -1
	}
	return true, id
}

func (ctx *ExeContext) usedPeerOutPublicKey(pk []byte) (bool, int) {
	var err error
	id := 0

	row := ctx.db.QueryRow("SELECT id  FROM outputs WHERE pk = ?;", pk)
	err = row.Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return false, -1
	}
	return true, id
}

func (ctx *ExeContext) getPeerOut(h []byte, out *User) (bool, int, int, error) {
	var err error
	used := 0
	id := 0

	if ctx.txModel >= 1 && ctx.txModel <= 5 {
		row := ctx.db.QueryRow("SELECT id, pk, n, data, used  FROM outputs WHERE h = ?;", h)
		err = row.Scan(&id, &out.Keys, &out.N, &out.Data, &used)
		if errors.Is(err, sql.ErrNoRows) {
			return false, -1, -1, err
		}
	} else if ctx.txModel == 6 {
		var outbuf []byte
		row := ctx.db.QueryRow("SELECT id, pk, n, data, Txns, used  FROM outputs WHERE h = ?;", h)
		err = row.Scan(&id, &out.Keys, &out.N, &out.Data, &outbuf, &used)
		if errors.Is(err, sql.ErrNoRows) {
			return false, -1, -1, err
		}
		// recover delta
		out.Txns = make([]int, len(outbuf)/4)
		out.UDelta = make([]byte, len(outbuf)/4*33)
		activity := make([]byte, 33)
		for i := 0; i < len(outbuf)/4; i++ {
			out.Txns[i] = byte4toInt(outbuf[i*4:])
			row = ctx.db.QueryRow("SELECT activity  FROM txHeaders WHERE txn = ?;", out.Txns[i])
			err = row.Scan(&activity)
			if errors.Is(err, sql.ErrNoRows) {
				return false, -1, -1, err
			}
			copy(out.UDelta[i*33:], activity)
		}
	}
	return true, id, used, nil
}

func (ctx *ExeContext) getPeerOutFromID(id int, out *User) (bool, int, error) {
	var err error
	used := 0

	if ctx.txModel >= 1 && ctx.txModel <= 5 {
		row := ctx.db.QueryRow("SELECT h, id, pk, n, data, used  FROM outputs WHERE id = ?;", id)
		err = row.Scan(&out.H, &out.Keys, &out.N, &out.Data, &used)
		if errors.Is(err, sql.ErrNoRows) {
			return false, -1, err
		}
	} else if ctx.txModel == 6 {
		var outbuf []byte
		row := ctx.db.QueryRow("SELECT h, pk, n, data, sig, Txns, used  FROM outputs WHERE id = ?;", id)
		err = row.Scan(&out.H, &out.Keys, &out.N, &out.Data, &out.sig, &outbuf, &used)
		if errors.Is(err, sql.ErrNoRows) {
			return false, -1, err
		}

		// recover delta
		out.Txns = make([]int, len(outbuf)/4)
		out.UDelta = make([]byte, len(outbuf)/4*33)
		activity := make([]byte, 33)
		for i := 0; i < len(outbuf)/4; i++ {
			out.Txns[i] = byte4toInt(outbuf[i*4:])
			row = ctx.db.QueryRow("SELECT activity  FROM txHeaders WHERE txn = ?;", out.Txns[i])
			err = row.Scan(&activity)
			if errors.Is(err, sql.ErrNoRows) {
				return false, -1, err
			}
			copy(out.UDelta[i*33:], activity)
		}
	}
	return true, used, nil
}

func (ctx *ExeContext) insertPeerTxHeader(txn int, tx *Transaction) (bool, error) {
	if ctx.txModel >= 1 && ctx.txModel <= 4 {
		// collect signatures into a byte array
		sigbuf := make([]byte, len(tx.Txh.Kyber)*int(ctx.sigContext.SigSize))
		if ctx.sigContext.SigType == 1 || ctx.sigContext.SigType == 2 {
			for i := 0; i < len(tx.Txh.Kyber); i++ {
				copy(sigbuf[i*int(ctx.sigContext.SigSize):], tx.Txh.Kyber[i])
			}
		} else {
			log.Fatal("unknown signature type:", ctx.sigContext.SigType)
		}
		// collect input ids into an int array
		inbuf := make([]byte, 4*len(tx.Data.Inputs))
		for i := 0; i < len(tx.Data.Inputs); i++ {
			inttoByte4(tx.Data.Inputs[i].u.id, inbuf[i*4:])
		}
		// collect output ids into an int array
		outbuf := make([]byte, 4*len(tx.Data.Outputs))
		for i := 0; i < len(tx.Data.Outputs); i++ {
			inttoByte4(tx.Data.Outputs[i].u.id, outbuf[i*4:])
			//fmt.Println("insert id (txH)", tx.Data.Outputs[i].u.id, tx.Data.Outputs[i].Pk)
		}
		stm, err := ctx.db.Prepare("INSERT INTO txHeaders(txn, sigAll, allInIds, allOutIds) VALUES(?, ?, ?, ?);")
		if err != nil {
			return false, err
		}
		defer stm.Close()
		_, err = stm.Exec(txn, sigbuf, inbuf, outbuf)
		if err != nil {
			return false, err
		}
	} else if ctx.txModel == 5 {
		stm, err := ctx.db.Prepare("INSERT INTO txHeaders(txn, activity, excess, sig) VALUES(?, ?, ?, ?);")
		if err != nil {
			return false, err
		}
		defer stm.Close()
		_, err = stm.Exec(txn, tx.Txh.activityProof, tx.Txh.excessPK, tx.Txh.Kyber[0])
		if err != nil {
			return false, err
		}
	} else if ctx.txModel == 6 {
		if len(tx.Txh.activityProof) != 33 {
			return false, errors.New("unverified transactions")
		}
		// collect output ids into an int array
		outbuf := make([]byte, 4*len(tx.Data.Outputs))
		for i := 0; i < len(tx.Data.Inputs); i++ {
			inttoByte4(tx.Data.Inputs[i].u.id, outbuf[i*4:])
		}
		for i := len(tx.Data.Inputs); i < len(tx.Data.Outputs); i++ {
			inttoByte4(tx.Data.Outputs[i].u.id, outbuf[i*4:])
		}
		stm, err := ctx.db.Prepare("INSERT INTO txHeaders(txn, activity, allOutIds) VALUES(?, ?, ?);")
		if err != nil {
			return false, err
		}
		defer stm.Close()
		_, err = stm.Exec(txn, tx.Txh.activityProof, outbuf)
		if err != nil {
			return false, err
		}
	}
	return true, nil
}

func (ctx *ExeContext) getStoredTx(txn int) (*Transaction, bool, *string) {
	var inBuf []byte
	var outBuf []byte
	var sigAll []byte
	id := 0
	used := 0

	var tx Transaction

	if ctx.txModel >= 1 && ctx.txModel <= 4 {
		// get txheader
		row := ctx.db.QueryRow("SELECT sigAll, allInIds, allOutIds  FROM txHeaders WHERE txn = ?;", txn)
		err := row.Scan(&sigAll, &inBuf, &outBuf)
		if errors.Is(err, sql.ErrNoRows) {
			errM := "could not find txn " + string(rune(txn))
			return nil, false, &errM
		}
		// get inputs
		tx.Data.Inputs = make([]InputData, len(inBuf)/4)
		for i := 0; i < len(inBuf)/4; i++ {
			tx.Data.Inputs[i].u.id = byte4toInt(inBuf[i*4:])
			row = ctx.db.QueryRow("SELECT h, pk, n, Data, used from outputs WHERE id = ?;", tx.Data.Inputs[i].u.id)
			err = row.Scan(&tx.Data.Inputs[i].Header, &tx.Data.Inputs[i].u.Keys, &tx.Data.Inputs[i].u.N, &tx.Data.Inputs[i].u.Data, &used)
			if errors.Is(err, sql.ErrNoRows) {
				errM := "could not find input id " + string(rune(id))
				return nil, false, &errM
			}
		}
		// get outputs
		tx.Data.Outputs = make([]OutputData, len(outBuf)/4)
		for i := 0; i < len(outBuf)/4; i++ {
			tx.Data.Outputs[i].u.id = byte4toInt(outBuf[i*4:])
			row = ctx.db.QueryRow("SELECT h, pk, n, Data, used from outputs WHERE id = ?;", tx.Data.Outputs[i].u.id)
			err = row.Scan(&tx.Data.Outputs[i].u.H, &tx.Data.Outputs[i].Pk, &tx.Data.Outputs[i].N, &tx.Data.Outputs[i].Data, &used)
			if errors.Is(err, sql.ErrNoRows) {
				errM := "could not find output id " + string(rune(id))
				return nil, false, &errM
			}
			//fmt.Println("got id (txH)", tx.Data.Outputs[i].u.id, tx.Data.Outputs[i].Pk)
		}
		// arrange signature
		if ctx.sigContext.SigType == 1 || ctx.sigContext.SigType == 2 {
			tx.Txh.Kyber = make([]Signature, len(sigAll)/int(ctx.sigContext.SigSize))
			for i := 0; i < len(sigAll)/int(ctx.sigContext.SigSize); i++ {
				tx.Txh.Kyber[i] = make([]byte, ctx.sigContext.SigSize)
				copy(tx.Txh.Kyber[i], sigAll[i*int(ctx.sigContext.SigSize):])
				//fmt.Println("sig:", i, tx.Txh.Kyber[i])
			}
		} else {
			log.Fatal("unknown sigType ", ctx.sigContext.SigType)
		}

	} else if ctx.txModel == 5 || ctx.txModel == 6 {
		log.Fatal("does not need ", ctx.txModel)
	} else {
		log.Fatal("unknown txModel ", ctx.txModel)
	}
	return &tx, true, nil
}

// getTxHeader returns headers data for origami utxo verification
func (ctx *ExeContext) getTxHeader(txn int, txh *TxHeader) (bool, *string) {
	row := ctx.db.QueryRow("SELECT activity, excess, sig  FROM txHeaders WHERE txn = ?;", txn)
	txh.Kyber = make([]Signature, 1)
	err := row.Scan(&txh.activityProof, &txh.excessPK, &txh.Kyber[0])
	if errors.Is(err, sql.ErrNoRows) {
		errM := "could not find txn " + string(rune(txn))
		return false, &errM
	}
	return true, nil
}

// setActivityTable arrange db data for origami account verification
func (ctx *ExeContext) setActivityTable() ([]bytes.Buffer, []byte, *string) {
	if ctx.txModel != 6 {
		log.Fatal("these functions are not needed")
	}
	temp := C.BN_new()
	d := C.BN_new()
	C.BN_set_bit(temp, 255) // one
	C.BN_set_bit(d, 255)

	activities := make([]bytes.Buffer, ctx.CurrentUsers)
	var activity []byte
	var outBuf []byte
	txn := 0
	id := 0

	stmt, err := ctx.db.Prepare("SELECT txn, activity, allOutIds  FROM txHeaders;")
	if err != nil {
		errM := err.Error()
		return nil, nil, &errM
	}
	defer stmt.Close()
	rows, err := stmt.Query()
	if err != nil {
		errM := err.Error()
		return nil, nil, &errM
	}
	defer rows.Close()

	for rows.Next() {
		rows.Scan(&txn, &activity, &outBuf)

		if len(activity) != 33 { // check current length
			errM := "invalid activity proof"
			return nil, nil, &errM
		}

		// update the prod of activities
		C.BN_bin2bn((*C.uchar)(unsafe.Pointer(&activity[0])), 33, temp)
		C.BN_mod_mul(d, d, temp, ctx.bnQ, ctx.bnCtx)

		for i := 0; i < len(outBuf)/4; i++ {
			for j := i + 1; j < len(outBuf)/4; j++ {
				if byte4toInt(outBuf[i*4:]) == byte4toInt(outBuf[j*4:]) {
					errM := "reused public keys"
					return nil, nil, &errM
				}
			}
		}

		for i := 0; i < len(outBuf)/4; i++ {
			id = byte4toInt(outBuf[i*4:])
			activities[id].Write(activity)
		}
	}
	activityProd := make([]byte, 33)
	C.BN_bn2binpad(d, (*C.uchar)(unsafe.Pointer(&activityProd[0])), 33)
	if err = rows.Err(); err != nil {
		errM := "could not read txHeaders"
		return nil, nil, &errM
	}
	return activities, activityProd, nil
}
