package txhelper

import (
	"fmt"
	"log"
	"math/rand"
	"os"
	"strconv"
	"testing"
	"time"
)

func (ctx *ExeContext) testClientTransactions(num int, tester *testing.T) {
	var txBytes []byte
	var tx1 Transaction
	for i := 0; i < num; i++ {
		tx := ctx.RandomTransaction()

		txBytes = ctx.ToBytes(tx)
		ok := ctx.FromBytes(txBytes, &tx1)
		if !ok {
			tester.Fatal("couldn't parse tx:", ctx.txModel, ctx.sigContext)
		}

		val, err := ctx.VerifyIncomingTransaction(tx)
		if !val {
			tester.Fatal("invalid transaction creation:"+*err, ctx.txModel, ctx.sigContext)
		}

		ctx.PrepareAppDataClient(&tx1.Data)
		val, err = ctx.VerifyIncomingTransaction(&tx1)
		if !val {
			tester.Fatal("invalid transaction convertion:"+*err, ctx.txModel)
		}

		ctx.UpdateAppDataClient(&tx.Data)
	}
}

func TestClients(tester *testing.T) {
	txNum := 1
	totalUsers := 3
	for i := 1; i <= 6; i++ {
		ctx := NewContext(100, 1, i, 1, 32, totalUsers, 2, 3, 1, false)
		ctx.testClientTransactions(txNum, tester)
		ctx = NewContext(100, 1, i, 2, 32, totalUsers, 2, 3, 1, false)
		ctx.testClientTransactions(txNum, tester)
	}

	txNum = 10
	totalUsers = 3
	for i := 1; i <= 6; i++ {
		ctx := NewContext(100, 1, i, 1, 32, totalUsers, 2, 3, 1, false)
		ctx.testClientTransactions(txNum, tester)
		ctx = NewContext(100, 1, i, 2, 32, totalUsers, 2, 3, 1, false)
		ctx.testClientTransactions(txNum, tester)
	}

	txNum = 10
	totalUsers = 10
	for i := 1; i <= 6; i++ {
		ctx := NewContext(100, 1, i, 1, 32, totalUsers, 4, 5, 1, false)
		ctx.testClientTransactions(txNum, tester)
		ctx = NewContext(100, 1, i, 2, 32, totalUsers, 4, 5, 1, false)
		ctx.testClientTransactions(txNum, tester)
	}
}

func TestPeers(tester *testing.T) {
	txNum := 1
	totalUsers := 3
	for i := 1; i <= 6; i++ {
		ctx := NewContext(100, 1, i, 1, 32, totalUsers, 2, 3, 1, false)
		ctx.testPeerTransactions(txNum, tester)
		ctx = NewContext(100, 1, i, 2, 32, totalUsers, 2, 3, 1, false)
		ctx.testPeerTransactions(txNum, tester)
	}

	txNum = 10
	totalUsers = 3
	for i := 1; i <= 6; i++ {
		ctx := NewContext(100, 1, i, 1, 32, totalUsers, 2, 3, 1, false)
		ctx.testPeerTransactions(txNum, tester)
		ctx = NewContext(100, 1, i, 2, 32, totalUsers, 2, 3, 1, false)
		ctx.testPeerTransactions(txNum, tester)
	}

	txNum = 10
	totalUsers = 10
	for i := 1; i <= 6; i++ {
		ctx := NewContext(100, 1, i, 1, 32, totalUsers, 4, 5, 1, false)
		ctx.testPeerTransactions(txNum, tester)
		ctx = NewContext(100, 1, i, 2, 32, totalUsers, 4, 5, 1, false)
		ctx.testPeerTransactions(txNum, tester)
	}
}

func (ctx *ExeContext) testPeerTransactions(num int, tester *testing.T) {
	var txBytes []byte
	var tx *Transaction
	var tx1 Transaction

	rand.NewSource(0)

	ctxClient := NewContext(ctx.exeId+115, 1, ctx.txModel, ctx.sigContext.SigType, ctx.payloadSize, ctx.TotalUsers, ctx.averageInputMax, ctx.averageOutputMax, ctx.distributionType, ctx.enableIndexing)
	ctxPeer := NewContext(ctx.exeId+115, 2, ctx.txModel, ctx.sigContext.SigType, ctx.payloadSize, ctx.TotalUsers, ctx.averageInputMax, ctx.averageOutputMax, ctx.distributionType, ctx.enableIndexing)

	for i := 0; i < num; i++ {
		tx = ctxClient.RandomTransaction()

		txBytes = ctxClient.ToBytes(tx)
		ok := ctxPeer.FromBytes(txBytes, &tx1)
		if !ok {
			tester.Fatal("couldn't parse tx:", ctxPeer.txModel, ctxPeer.sigContext)
		}

		val, err := ctxClient.VerifyIncomingTransaction(tx)
		if !val {
			tester.Fatal("invalid transaction convertion in the client:"+*err, ctx.txModel)
		}

		ctxClient.UpdateAppDataClient(&tx.Data)

		val, err = ctxPeer.VerifyIncomingTransaction(&tx1)
		if !val {
			tester.Fatal("invalid transaction convertion in the peer:"+*err, ctx.txModel)
		}

		val, err = ctxPeer.UpdateAppDataPeer(i, &tx1)
		if !val {
			tester.Fatal("could not update tx in the peer:"+*err, ctx.txModel)
		}
		val, err = ctxPeer.InsertTxHeader(i, &tx1)
		if !val {
			tester.Fatal("could not insert tx header in the peer:"+*err, ctx.txModel)
		}
	}

	val, err := ctxPeer.VerifyStoredAllTransaction()
	if !val {
		tester.Fatal("invalid blockchain was created:" + *err)
	}
}

func TestPeersBatch(tester *testing.T) {
	txNum := 10
	totalUsers := 10
	for i := 1; i <= 6; i++ {
		ctx := NewContext(100, 1, i, 1, 32, totalUsers, 4, 5, 1, false)
		ctx.testPeerBatchTransactions(txNum, tester)
		ctx = NewContext(100, 1, i, 2, 32, totalUsers, 4, 5, 1, false)
		ctx.testPeerBatchTransactions(txNum, tester)
	}
}

func (ctx *ExeContext) testPeerBatchTransactions(num int, tester *testing.T) {
	var txBytes []byte
	batchSize := 3
	tx := make([]*Transaction, batchSize)
	tx1 := make([]Transaction, batchSize)

	rand.NewSource(0)

	ctxClient := NewContext(ctx.exeId+115, 1, ctx.txModel, ctx.sigContext.SigType, ctx.payloadSize, ctx.TotalUsers, ctx.averageInputMax, ctx.averageOutputMax, ctx.distributionType, ctx.enableIndexing)
	ctxPeer := NewContext(ctx.exeId+115, 2, ctx.txModel, ctx.sigContext.SigType, ctx.payloadSize, ctx.TotalUsers, ctx.averageInputMax, ctx.averageOutputMax, ctx.distributionType, ctx.enableIndexing)

	for i := 0; i < num; i++ {

		for j := 0; j < batchSize; j++ {
			tx[j] = ctxClient.RandomTransaction()

			val, err := ctxClient.VerifyIncomingTransaction(tx[j])
			if !val {
				tester.Fatal("invalid transaction conversion in the client:"+*err, ctx.txModel)
			}

			val, errM := ctxClient.UpdateAppDataClient(&tx[j].Data)
			if !val {
				tester.Fatal("invalid transaction conversion in the client:"+errM.Error(), ctx.txModel)
			}
		}

		for j := 0; j < batchSize; j++ {
			txBytes = ctxClient.ToBytes(tx[j])
			ok := ctxPeer.FromBytes(txBytes, &tx1[j])
			if !ok {
				tester.Fatal("couldn't parse tx:", ctxPeer.txModel, ctxPeer.sigContext)
			}

			val, err := ctxPeer.VerifyIncomingTransactionWithTemp(&tx1[j])
			if !val {
				tester.Fatal("invalid transaction in the peer:"+*err, ctx.txModel, i, j)
			}

			val, err = ctxPeer.UpdateAppDataPeerToTemp(i*batchSize+j, &tx1[j])
			if !val {
				tester.Fatal("could not update tx in the peer:"+*err, ctx.txModel, i, j)
			}
		}

		for j := 0; j < batchSize; j++ {
			val, err := ctxPeer.UpdateAppDataPeer(i*batchSize+j, &tx1[j])
			if !val {
				tester.Fatal("could not update tx in the peer:"+*err, ctx.txModel)
			}
			val, err = ctxPeer.InsertTxHeader(i*batchSize+j, &tx1[j])
			if !val {
				tester.Fatal("could not insert tx header in the peer:"+*err, ctx.txModel)
			}
		}
	}

	val, err := ctxPeer.VerifyStoredAllTransaction()
	if !val {
		tester.Fatal("invalid blockchain was created:", ctxPeer.txModel, *err)
	}

}

// This a sample benchmark
func BenchmarkExeContext_VerifyStoredAllTransactionPeers(tester *testing.B) {
	txNum := 100
	totalUsers := 100
	testRandomTransactionPeer(1, txNum, totalUsers, tester, false)
	testRandomTransactionPeer(2, txNum, totalUsers, tester, false)
	testRandomTransactionPeer(1, txNum, totalUsers, tester, true)
	testRandomTransactionPeer(2, txNum, totalUsers, tester, true)
}

func testRandomTransactionPeer(sigType int32, txNum int, totalUsers int, tester *testing.B, enableIndexing bool) {
	var txBytes []byte
	var tx *Transaction
	var tx1 Transaction

	for txType := 1; txType <= 6; txType++ {
		averageInSize := 0
		averageOutSize := 0
		averageTxSize := 0
		averageTxVerTime := time.Duration(0)
		averageUpdateTime := time.Duration(0)
		rand.NewSource(0)

		ctxClient := NewContext(100+txType, 1, txType, sigType, 32, totalUsers, 4, 5, 1, enableIndexing)
		ctxPeer := NewContext(100+txType, 2, txType, sigType, 32, totalUsers, 4, 5, 1, enableIndexing)

		for i := 0; i < txNum; i++ {
			tx = ctxClient.RandomTransaction()

			txBytes = ctxClient.ToBytes(tx)
			ok := ctxPeer.FromBytes(txBytes, &tx1)
			if !ok {
				tester.Fatal("couldn't parse tx:", ctxPeer.txModel, ctxPeer.sigContext)
			}

			averageTxSize += len(txBytes)

			_, err := ctxClient.VerifyIncomingTransaction(tx)
			ctxClient.UpdateAppDataClient(&tx.Data)
			if err != nil {
				fmt.Println(i, *err)
			}

			start := time.Now()
			_, err = ctxPeer.VerifyIncomingTransaction(&tx1)
			averageTxVerTime += time.Since(start)

			start = time.Now()
			ctxPeer.UpdateAppDataPeer(i, &tx1)
			ctxPeer.InsertTxHeader(i, &tx1)
			averageUpdateTime += time.Since(start)
			if err != nil {
				log.Fatal(i, *err)
			}
			averageInSize += len(tx1.Data.Inputs)
			averageOutSize += len(tx1.Data.Outputs)
		}
		var val bool
		var err *string
		start := time.Now()
		for i := 0; i < tester.N; i++ {
			val, err = ctxPeer.VerifyStoredAllTransaction()
		}
		timeElapsed := time.Since(start)
		result = val
		if err != nil || val == false {
			tester.Fatal("verification failed:", val, ", ", *err)
		} else {
			file, err := os.Open("peer" + strconv.FormatInt(int64(ctxPeer.exeId), 10) + ".db")
			if err != nil {
				log.Fatal(err)
			}
			fi, err := file.Stat()
			if err != nil {
				log.Fatal(err)
			}
			fmt.Println("verification passed:", ctxPeer.txModel, 32, timeElapsed, ctxPeer.TotalTx, ctxPeer.TotalUsers,
				ctxPeer.CurrentUsers, ctxPeer.CurrentOutputs, ctxPeer.DeletedOutputs, averageTxSize/txNum,
				averageTxVerTime/time.Duration(txNum), averageUpdateTime/time.Duration(txNum), float32(averageInSize)/float32(txNum),
				float32(averageOutSize)/float32(txNum), fi.Size())
		}
	}
}
