package txhelper

// CreateBlock filters valid transactions and outputs txRootHash to be included in consensus data.
// Also, it returns converted transactions which can be easily inserted into the tx database.
func (ctx *ExeContext) CreateBlock(txsBytes [][]byte) (txRootHash []byte, txs []*Transaction) {

	return nil, nil
}

// VerifyBlock verifies all transactions and outputs txRootHash to be included in consensus data.
// Also, it returns converted transactions which can be easily inserted into the tx database.
func (ctx *ExeContext) VerifyBlock(txsBytes [][]byte) (txRootHash []byte, txs []*Transaction) {
	return nil, nil
}

// VerifyAllBlocks checks if stored transactions are valid according to the root hashes stored in consensus proofs
func (ctx *ExeContext) VerifyAllBlocks(txRootHashes [][]byte) (bool, *string) {
	return true, nil
}
