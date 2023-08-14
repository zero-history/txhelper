package txhelper

import (
	"database/sql"
	"encoding/json"
	"errors"
	_ "github.com/mattn/go-sqlite3"
	"log"
	"strconv"
)

type User struct {
	id     int
	H      []byte `json:"H"`      // hash
	N      uint8  `json:"N"`      // number of outputs created by the user
	Keys   []byte `json:"Keys"`   // pk with/out sk
	Data   []byte `json:"Data"`   // most recent application Data
	UDelta []byte `json:"UDelta"` // could be empty
	Txns   []int  `json:"txns"`   // for origami-header identifier
	sig    []byte // for origami-header identifier
}

func (ctx *ExeContext) initClientDB() {
	var err error

	ctx.db, err = sql.Open("sqlite3", "client"+strconv.FormatInt(int64(ctx.exeId), 10)+".db")
	if err != nil {
		log.Fatal(err)
	}

	statement := "DROP TABLE IF EXISTS outputs; " +
		"CREATE TABLE outputs(id INTEGER PRIMARY KEY, h BLOB, Data BLOB);"

	_, err = ctx.db.Exec(statement)

	if err != nil {
		log.Fatal(err)
	}
}

func (ctx *ExeContext) insertClientOut(id int, out *User) {
	var err error
	var data []byte

	stm, err := ctx.db.Prepare("INSERT INTO outputs(id, h, Data) VALUES(?, ?, ?);")
	if err != nil {
		log.Fatal(err)
	}
	defer stm.Close()

	data, err = json.Marshal(out)
	if err != nil {
		log.Fatal("Error insertClientOut:", err)
	}
	_, err = stm.Exec(id, out.H, data)

	if err != nil {
		log.Fatal(err)
	}
}

func (ctx *ExeContext) getClientOut(id int, out *User) bool {
	var err error
	var data []byte

	row := ctx.db.QueryRow("SELECT data FROM outputs WHERE id = ?", id)
	err = row.Scan(&data)
	if errors.Is(err, sql.ErrNoRows) {
		log.Print("could not find id ", id)
		return false
	}
	err = json.Unmarshal(data, out)
	if err != nil {
		log.Fatal("Error getClientOut:", err)
	}
	return true
}

func (ctx *ExeContext) updateClientOut(id int, out *User) {
	var err error
	var data []byte

	data, err = json.Marshal(out)
	if err != nil {
		log.Fatal(err)
	}
	stm, err := ctx.db.Prepare("UPDATE outputs SET h = ?, data = ? WHERE id = ?")
	if err != nil {
		log.Fatal("Error updateClientOut:", err)
	}
	defer stm.Close()

	_, err = stm.Exec(out.H, data, id)
}

func (ctx *ExeContext) getClientOutFromH(h []byte, out *User) bool {
	var err error
	var data []byte

	row := ctx.db.QueryRow("SELECT data FROM outputs WHERE h = ?", h)
	err = row.Scan(&data)
	if errors.Is(err, sql.ErrNoRows) {
		return false
	}
	err = json.Unmarshal(data, out)
	if err != nil {
		log.Fatal("Error getClientOutFromH 2:", err)
	}
	return true
}

func (ctx *ExeContext) updateClientOutFromH(h []byte, out *User) {
	var err error
	var data []byte

	data, err = json.Marshal(out)
	if err != nil {
		log.Fatal(err)
	}
	stm, err := ctx.db.Prepare("UPDATE outputs SET h = ?, data = ? WHERE h = ?")
	if err != nil {
		log.Fatal("Error updateClientOut:", err)
	}
	defer stm.Close()

	_, err = stm.Exec(out.H, data, h)
}
