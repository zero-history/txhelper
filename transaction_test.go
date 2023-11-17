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
			tester.Fatal("couldn't parse tx:", ctx.txModel, ctx.sigContext.SigType)
		}

		val, err := ctx.VerifyIncomingTransaction(tx)
		if !val {
			tester.Fatal("invalid transaction creation:"+*err, ctx.txModel, ctx.sigContext.SigType)
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
		ctx := NewContext(100, 1, i, 1, 32, totalUsers, 2, 3, 1, false, 2)
		ctx.testClientTransactions(txNum, tester)
		ctx = NewContext(100, 1, i, 2, 32, totalUsers, 2, 3, 1, false, 2)
		ctx.testClientTransactions(txNum, tester)
	}

	txNum = 10
	totalUsers = 3
	for i := 1; i <= 6; i++ {
		ctx := NewContext(100, 1, i, 1, 32, totalUsers, 2, 3, 1, false, 2)
		ctx.testClientTransactions(txNum, tester)
		ctx = NewContext(100, 1, i, 2, 32, totalUsers, 2, 3, 1, false, 2)
		ctx.testClientTransactions(txNum, tester)
	}

	txNum = 10
	totalUsers = 10
	for i := 1; i <= 6; i++ {
		ctx := NewContext(100, 1, i, 1, 32, totalUsers, 4, 5, 1, false, 2)
		ctx.testClientTransactions(txNum, tester)
		ctx = NewContext(100, 1, i, 2, 32, totalUsers, 4, 5, 1, false, 2)
		ctx.testClientTransactions(txNum, tester)
	}
}

func TestPeers(tester *testing.T) {
	txNum := 1
	totalUsers := 3
	for i := 1; i <= 6; i++ {
		ctx := NewContext(100, 1, i, 1, 32, totalUsers, 2, 3, 1, false, 2)
		ctx.testPeerTransactions(txNum, tester)
		//ctx = NewContext(100, 1, i, 2, 32, totalUsers, 2, 3, 1, false)
		//ctx.testPeerTransactions(txNum, tester)
	}

	txNum = 2
	totalUsers = 3
	for i := 1; i <= 6; i++ {
		ctx := NewContext(100, 1, i, 1, 32, totalUsers, 2, 3, 1, false, 2)
		ctx.testPeerTransactions(txNum, tester)
		ctx = NewContext(100, 1, i, 2, 32, totalUsers, 2, 3, 1, false, 2)
		ctx.testPeerTransactions(txNum, tester)
	}

	txNum = 10
	totalUsers = 10
	for i := 1; i <= 6; i++ {
		ctx := NewContext(100, 1, i, 1, 32, totalUsers, 4, 5, 1, false, 2)
		ctx.testPeerTransactions(txNum, tester)
		ctx = NewContext(100, 1, i, 2, 32, totalUsers, 4, 5, 1, false, 2)
		ctx.testPeerTransactions(txNum, tester)
	}
}

func (ctx *ExeContext) testPeerTransactions(num int, tester *testing.T) {
	var txBytes []byte
	var tx *Transaction
	var tx1 Transaction

	rand.NewSource(0)

	ctxClient := NewContext(ctx.exeId+115, 1, ctx.txModel, ctx.sigContext.SigType, ctx.payloadSize, ctx.TotalUsers, ctx.averageInputMax, ctx.averageOutputMax, ctx.distributionType, ctx.enableIndexing, ctx.PublicKeyReuse)
	ctxPeer := NewContext(ctx.exeId+115, 2, ctx.txModel, ctx.sigContext.SigType, ctx.payloadSize, ctx.TotalUsers, ctx.averageInputMax, ctx.averageOutputMax, ctx.distributionType, ctx.enableIndexing, ctx.PublicKeyReuse)

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
		ctx := NewContext(100, 1, i, 1, 32, totalUsers, 4, 5, 1, false, 2)
		ctx.testPeerBatchTransactions(txNum, tester)
		ctx = NewContext(100, 1, i, 2, 32, totalUsers, 4, 5, 1, false, 2)
		ctx.testPeerBatchTransactions(txNum, tester)
	}
}

func (ctx *ExeContext) testPeerBatchTransactions(num int, tester *testing.T) {
	var txBytes []byte
	batchSize := 3
	tx := make([]*Transaction, batchSize)
	tx1 := make([]Transaction, batchSize)

	rand.NewSource(0)

	ctxClient := NewContext(ctx.exeId+115, 1, ctx.txModel, ctx.sigContext.SigType, ctx.payloadSize, ctx.TotalUsers, ctx.averageInputMax, ctx.averageOutputMax, ctx.distributionType, ctx.enableIndexing, ctx.PublicKeyReuse)
	ctxPeer := NewContext(ctx.exeId+115, 2, ctx.txModel, ctx.sigContext.SigType, ctx.payloadSize, ctx.TotalUsers, ctx.averageInputMax, ctx.averageOutputMax, ctx.distributionType, ctx.enableIndexing, ctx.PublicKeyReuse)

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

func testFixedTransactionPeer(sigType int32, txNum int, inSize uint8, outSize uint8, totalUsers int, payload uint16, tester *testing.B, enableIndexing bool) {
	var txBytes []byte
	var tx *Transaction
	var tx1 Transaction

	for txType := 1; txType <= 6; txType++ {
		averageTxSize := 0
		averageTxVerTime := time.Duration(0)
		averagePrepareTime := time.Duration(0)
		averageUTime := time.Duration(0)
		averageHeaderTime := time.Duration(0)
		rand.NewSource(0)

		ctxClient := NewContext(100+txType, 1, txType, sigType, payload, totalUsers, 1, 3, 1, enableIndexing, 1)
		ctxPeer := NewContext(100+txType, 2, txType, sigType, payload, totalUsers, 1, 3, 1, enableIndexing, 1)
		//ctxPeerTemp := NewContext(100+txType, 2, txType, sigType, payload, totalUsers, 1, 3, 1, enableIndexing, 1)

		for i := 0; i < txNum; i++ {
			tx = ctxClient.RandomTransaction()

			txBytes = ctxClient.ToBytes(tx)
			ok := ctxPeer.FromBytes(txBytes, &tx1)
			if !ok {
				tester.Fatal("couldn't parse tx:", ctxPeer.txModel, ctxPeer.sigContext)
			}

			_, err := ctxClient.VerifyIncomingTransaction(tx)
			ok, _ = ctxClient.UpdateAppDataClient(&tx.Data)
			if !ok {
				tester.Fatal("could not update")
			}
			if err != nil {
				fmt.Println(i, *err)
			}

			_, err = ctxPeer.VerifyIncomingTransaction(&tx1)

			ctxPeer.UpdateAppDataPeer(i, &tx1)
			ctxPeer.InsertTxHeader(i, &tx1)

			if err != nil {
				log.Fatal(i, *err)
			}

			/*_, err = ctxPeerTemp.VerifyIncomingTransactionWithTemp(&tx1)

			ctxPeerTemp.UpdateAppDataPeerToTemp(i, &tx1)
			//ctxPeerTemp.InsertTxHeader(i, &tx1)

			if err != nil {
				log.Fatal(i, *err)
			}*/
		}
		for i := txNum; i < txNum+1; i++ {
			tx = ctxClient.FixedTransaction(inSize, outSize)

			txBytes = ctxClient.ToBytes(tx)
			ok := ctxPeer.FromBytes(txBytes, &tx1)
			if !ok {
				tester.Fatal("couldn't parse tx:", ctxPeer.txModel, ctxPeer.sigContext)
			}

			averageTxSize += len(txBytes)

			//_, err := ctxClient.VerifyIncomingTransaction(tx)
			ok, _ = ctxClient.UpdateAppDataClient(&tx.Data)

			for trial := 0; trial < 100; trial++ {
				start := time.Now()
				_, err := ctxPeer.PrepareAppDataPeer(&tx1.Data)
				averagePrepareTime += time.Since(start)
				if err != nil {
					errM := err.Error()
					log.Fatal(i, errM)
				}

				start = time.Now()
				ok, err1 := ctxPeer.checkUniqueness(&tx1)
				averageUTime += time.Since(start)
				if !ok {
					log.Fatal(i, err1)
				}

				start = time.Now()
				ok, err2 := ctxPeer.VerifyTxHeader(&tx1.Txh, &tx1.Data)
				averageHeaderTime += time.Since(start)
				if !ok {
					log.Fatal(i, err2)
				}
			}

			ctxPeer.UpdateAppDataPeer(i, &tx1)
			ctxPeer.InsertTxHeader(i, &tx1)

			/*for trial:= 0; trial <100; trial++ {
				start := time.Now()
				_, err := ctxPeerTemp.VerifyIncomingTransactionWithTemp(&tx1)
				averageTxVerTime += time.Since(start)

				if err != nil {
					log.Fatal(i, *err)
				}
			}

			ctxPeerTemp.UpdateAppDataPeerToTemp(i, &tx1)
			//ctxPeer.InsertTxHeader(i, &tx1)*/
		}
		ctxClient.db.Close()
		ctxPeer.db.Close()
		os.Remove("client" + strconv.FormatInt(int64(100+txType), 10) + ".db")
		os.Remove("peer" + strconv.FormatInt(int64(100+txType), 10) + ".db")

		fmt.Println(txType, sigType, payload, averageTxVerTime/time.Duration(100), averagePrepareTime/time.Duration(100),
			averageUTime/time.Duration(100), averageHeaderTime/time.Duration(100), (averagePrepareTime+averageUTime+averageHeaderTime)/time.Duration(100))
	}
}

// This a sample benchmark
func BenchmarkExeContext_VerifyStoredAllTransactionPeers26(tester *testing.B) {
	txNum := 5
	totalUsers := 15
	testFixedTransactionPeer(1, txNum, 2, 3, totalUsers, 256, tester, true)
	testFixedTransactionPeer(2, txNum, 2, 3, totalUsers, 256, tester, true)
}

// This a sample benchmark
func BenchmarkExeContext_VerifyStoredAllTransactionPeers27(tester *testing.B) {
	txNum := 5
	totalUsers := 15
	testFixedTransactionPeer(1, txNum, 2, 3, totalUsers, 512, tester, true)
	testFixedTransactionPeer(2, txNum, 2, 3, totalUsers, 512, tester, true)
}

// This a sample benchmark
func BenchmarkExeContext_VerifyStoredAllTransactionPeers29(tester *testing.B) {
	txNum := 5
	totalUsers := 15
	testFixedTransactionPeer(1, txNum, 2, 3, totalUsers, 1024, tester, true)
	testFixedTransactionPeer(2, txNum, 2, 3, totalUsers, 1024, tester, true)
}

// This a sample benchmark
func BenchmarkExeContext_VerifyStoredAllTransactionPeers210(tester *testing.B) {
	txNum := 5
	totalUsers := 15
	testFixedTransactionPeer(1, txNum, 2, 3, totalUsers, 2048, tester, true)
	testFixedTransactionPeer(2, txNum, 2, 3, totalUsers, 2048, tester, true)
}

// This a sample benchmark
func BenchmarkExeContext_VerifyStoredAllTransactionPeers211(tester *testing.B) {
	txNum := 5
	totalUsers := 120
	testFixedTransactionPeer(1, txNum, 2, 3, totalUsers, 3072, tester, true)
	testFixedTransactionPeer(2, txNum, 2, 3, totalUsers, 3072, tester, true)
}

// This a sample benchmark
func BenchmarkExeContext_VerifyStoredAllTransactionPeers212(tester *testing.B) {
	txNum := 5
	totalUsers := 15
	testFixedTransactionPeer(1, txNum, 2, 3, totalUsers, 4096, tester, true)
	testFixedTransactionPeer(2, txNum, 2, 3, totalUsers, 4096, tester, true)
}

func testRandomTransactionPeer(sigType int32, txNum int, totalUsers int, payload uint16, tester *testing.B, enableIndexing bool) {
	var txBytes []byte
	var tx *Transaction
	var tx1 Transaction
	block := 0

	for txType := 1; txType <= 6; txType++ {
		averageInSize := 0
		averageOutSize := 0
		averageTxSize := 0
		averageTxVerTime := time.Duration(0)
		rand.NewSource(0)

		ctxClient := NewContext(100+txType, 1, txType, sigType, payload, totalUsers, 3, 5, 1, enableIndexing, 1)
		ctxPeer := NewContext(100+txType, 2, txType, sigType, payload, totalUsers, 3, 5, 1, enableIndexing, 1)

		for i := 0; i < txNum; i++ {
			block++

			if block == 200 {
				tx = ctxClient.FixedTransaction(2, 3)
			} else {
				tx = ctxClient.RandomTransaction()
			}

			txBytes = ctxClient.ToBytes(tx)
			ok := ctxPeer.FromBytes(txBytes, &tx1)
			if !ok {
				tester.Fatal("couldn't parse tx:", ctxPeer.txModel, ctxPeer.sigContext)
			}

			averageTxSize += len(txBytes)

			_, err := ctxClient.VerifyIncomingTransaction(tx)
			ok, _ = ctxClient.UpdateAppDataClient(&tx.Data)
			if !ok {
				tester.Fatal("could not update")
			}
			if err != nil {
				fmt.Println(i, *err)
			}

			if block == 500 {
				averageTxVerTime = time.Duration(0)
				for trial := 0; trial < 100; trial++ {
					start := time.Now()
					_, err = ctxPeer.VerifyIncomingTransaction(&tx1)
					averageTxVerTime += time.Since(start)
				}
			}

			_, err = ctxPeer.VerifyIncomingTransaction(&tx1)
			ctxPeer.UpdateAppDataPeer(i, &tx1)
			ctxPeer.InsertTxHeader(i, &tx1)

			if err != nil {
				log.Fatal(i, *err)
			}
			averageInSize += len(tx1.Data.Inputs)
			averageOutSize += len(tx1.Data.Outputs)

			if block == 500 {
				var val bool
				var err *string
				start := time.Now()
				for i := 0; i < tester.N; i++ {
					val, err = ctxPeer.VerifyStoredAllTransaction()
				}
				ChainVerification := time.Since(start)
				result = val
				if err != nil || val == false {
					tester.Fatal("verification failed:", val, ", ", *err)
				}

				start = time.Now()
				for i := 0; i < tester.N; i++ {
					val, err = ctxPeer.VerifyStoredAllTransaction()
				}
				ChainVerification += time.Since(start)
				result = val
				if err != nil || val == false {
					tester.Fatal("verification failed:", val, ", ", *err)
				}

				start = time.Now()
				for i := 0; i < tester.N; i++ {
					val, err = ctxPeer.VerifyStoredAllTransaction()
				}
				ChainVerification += time.Since(start)
				result = val
				if err != nil || val == false {
					tester.Fatal("verification failed:", val, ", ", *err)
				}

				file, err1 := os.Open("peer" + strconv.FormatInt(int64(ctxPeer.exeId), 10) + ".db")
				if err1 != nil {
					log.Fatal(err1)
				}
				fi, err2 := file.Stat()
				if err2 != nil {
					log.Fatal(err2)
				}
				fmt.Println(ctxPeer.txModel, ctxPeer.sigContext.SigType, ctxPeer.payloadSize, ChainVerification/3, ctxPeer.TotalTx, ctxPeer.TotalUsers,
					ctxPeer.CurrentUsers, ctxPeer.CurrentOutputs, ctxPeer.DeletedOutputs, averageTxSize/txNum,
					averageTxVerTime/time.Duration(30), float32(averageOutSize)/float32(txNum), fi.Size())
				block = 0
			}
		}

		ctxClient.db.Close()
		ctxPeer.db.Close()
		os.Remove("client" + strconv.FormatInt(int64(100+txType), 10) + ".db")
		os.Remove("peer" + strconv.FormatInt(int64(100+txType), 10) + ".db")
	}
}

// This a fixed benchmark
func BenchmarkExeContext_VerifyStoredAllTransactionPeers1(tester *testing.B) {
	txNum := 5000
	totalUsers := 5000
	testRandomTransactionPeer(1, txNum, totalUsers, 8, tester, true)
	testRandomTransactionPeer(2, txNum, totalUsers, 8, tester, true)
}
