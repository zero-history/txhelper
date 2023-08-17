# TxHelper - Blockchain Transaction Layer Simulator

Blockchain transaction models differently impact blockchain
consensus. TxHelper provides the functionalities required to simulate these
different transaction models for consensus benchmarks easily. Currently, txHelper supports 6 different
transaction models with two digital signatures. It also allows changing application-specific data, such as the average
payload size and the average number of inputs/outputs per transaction to simulate different applications.

## What is a blockchain transaction?
Blockchains are live databases with applications. In some cases,
the application is a decentralized bank that transfers money between users securely while
data blockchains' application may be a decentralized file system.
A transaction is a technical term used to represent an individual application update, e.g.,
money transferring or updating a file(s). A generic transaction contains inputs, outputs, and
a transaction header. An input is a piece of application data that already exists, and an
output is the application data that will replace those inputs. For example,
an input could be an identifier to a blockchain file, and the output could be the updated version of that
file. Another example would be that an input user is transferring some coins to
an output user. In both cases, the transaction header contains cryptographic data (digital signatures and zero-knowledge proofs) to prove that
the application update is correct and authenticated by input owners. However, in some cases, the applications
may want accountability, which means the output owners must authorize the transaction, e.g.,
owners of files or accountable-auditable cash systems where users are only allowed to pay if the receivers authorize them.

## Transaction Models

TxHelper supports the following transaction 6 models.

| Transaction Model                | Transaction Type | Transaction Header                                 | Currently supported Signatures |
|----------------------------------|------------------|----------------------------------------------------|--------------------------------|
| Classic UTXO (1)                 | Non-Zero-History | Signatures of input owners                         | Schnorr, Aggregated BLS        |
| Classic Accounts (2)             | Non-Zero-History | Signature of input owner                           | Schnoor, Aggregated BLS        |
| Classic Accountable UTXO (3)     | Non-Zero-History | Signatures of input + output owners                | Schnorr, Aggregated BLS        |
| Classic Accountable Accounts (4) | Non-Zero-History | Signatures of input + output owners                | Schnorr, Aggregated BLS        |
| Origami UTXO (5)                 | Zero-History     | Activity-proof, excess and a difference-signature  | Schnorr, BLS                   |
| Origami Accounts (6)             | Zero-History     | Activity-proof and signatures of all output owners | Schnorr, Aggregated BLS        |

### Application Simulation

TxHelper simulates a generic application where you can set the average payload (average size of an output/input),
and the average number of inputs and outputs per transaction. For example, the payload of a cryptocurrency
is 8 bytes plus average contract size (for plain-text coins) or roughly 800 bytes (for confidential coins), while the payload could be higher as
2KB for file systems.

### Tradeoffs of Models
The most suitable transaction model for an application depends on the application-specific requirements since each transaction
model has some tradeoffs. The simplest example is the difference between the UTXO model and the account model. In the account model,
each public key has **only one state**, and a transaction takes that state and modify into a new state.
Hence, the account-based transactions, inputs are the identifiers to the accounts, and outputs contain the new
state. Unless an output belongs to a new account, the output does not need to mention the public key, which can
be recovered from reading the blockchain via the input identifier. However, this efficiency comes at the cost of additional
database queries to make sure that the new public keys were not used before.

In UTXO (Unspent Transaction Outputs) model, each output has a public key associated with them, and multiple outputs
may belong to the **same public key**. Hence, verifiers do not need to run database queries on unique public keys,
but there is a tradeoff on transaction size since all new public keys must be stated in the transaction.

In summary, if the users prefer to create a new public key frequently, then the UTXO model is a better option. However, if the users
tend to keep the public keys for the long term, then an account model is a better option.

TxHelper helps to identify what happens to blockchain performance with different application requirements and
transaction models, so the best transaction model can be selected.


### Tradeoffs of Signatures

Digital signatures (or some unforgeable proofs) are required to verify that the owners authorized the transaction.
Hence, digital signature has a significant impact on blockchain performance. TxHelper currently supports two digital signatures,
Schnorr signatures and aggregated BLS signatures.

| Signature      | Public Key Size | Signature Size | Public Aggregation | Verification Time        |
|----------------|-----------------|----------------|--------------------|--------------------------|
| Schnorr        | 32              | 64             | No                 | O(number of public keys) |
| Aggregated BLS | 128             | 32             | Yes                | O(number of public keys) | 


Even though BLS signatures are shorter and can be aggregated, they typically take more time for verification.
Once the other hand, Schnorr public keys are shorter and take less time to verify but cannot publicly aggregate signatures.
Hence, the choice of the signature depends on how frequently the new public keys are created and whether the transaction
model is UTXO or account-based. 

### Tradeoffs of Zero-History and Non-Zero-History

In blockchains, the consensus proofs show the accepted transactions. In non-zero-history blockchains, verifiers cannot verify
the consensus proofs without the history of the blockchain, e.g., spent UXTO or an old account state. Hence, a self-verifiable
blockchain is catastrophically large, and the startup time can be days. However, in zero-history blockchains, the consensus
proof can be verified without the history, and they are immutable (there is only one valid zero-history blockchain per consensus proof set)
due to a special proof called activity proof (32 bytes per transaction). 
Therefore, these blockchains significantly reduce the size and decrease the startup time of new peers.

However, zero-history blockchains only perform better than non-zero-history blockchains if there is an application history.
For example, if there are only new accounts but no account is being modified, then zero-history blockchains will be
larger than non-zero-history blockchains due to activity proofs and no history to delete. However, in real applications,
zero-history blockchains are significantly  shorter than non-zero-history blockchains.



## Setting up TxHelper

In a blockchain network, clients create and send transactions to peers (miners). First, we
need to create two TxHelper contexts for clients and peers. For example,

```go
ctxClient := NewContext(clientId, 1, txModel, SigType, averageSize, totalUsers, averageInputMax, averageOutputMax, distributionType)

ctxPeer := NewContext(peerId, 2, txModel, SigType, averageSize, totalUsers, averageInputMax, averageOutputMax, distributionType)
```

Note that these peer contexts should be included with your consensus peers/nodes.

Here, ``clientId`` and ``peerId`` is used to identify each context separately. For clients,
``uType = 1`` and for peers, ``uType = 2``. TxHelper supports two signatures, Schnorr signatures (``sigType = 1``) and BLS signatures (``sigType = 2``) on
elliptic curves. Note that both client(s) and peer(s) must have the same variables. We will explain other variables in the next section.

### Random Transaction Generation

Once we have the contexts, we can create a sequence of random transactions to create new UTXO/accounts
and update existing UTXO and accounts.

```go
var tx *Transaction
tx = ctxClient.RandomTransaction()
```

Here, TxHelper randomly chooses the input size from [0, ``averageInputMax``] and the output size from [0, ``averageOutputMax``].
If there are not enough inputs, the input size will be updated, e.g., the first transaction will always have zero inputs.
Each transaction output will contain an ``average size ``a number of random bytes as the simulated payload of the application.
Note that we can limit the total unique public keys in the system via
``totalUsers``, except for Origami UTXO. If current accounts or unique public keys have exceeded,
transactions will not create any new accounts or users with new public keys. In account-based transactions,
the input size will be equal to the output size in that case. 

### Saving and Verification

Once the transaction is created, we can get bytes of the transaction to send the peers. Also, peers
can convert bytes into a transaction after receiving them (note that TxHelper does not provide network
functionalities). For example,

```go
txBytes = ctxClient.ToBytes(tx)  // to send

var tx1 Transaction
ctxPeer.FromBytes(txBytes, &tx1) // after receiving
```

Then peers verify the transactions and add them to the blockchain. In consensus testing, the peers propose blocks with verified transactions.
Once the block passes the consensus phase, all transactions will be inserted into the blockchain.

```go
val, err = ctxPeer.VerifyIncomingTransaction(&tx1) // Peer verify the transactions before sending
if val == true {
    ctxPeer.UpdateAppDataPeer(i, &tx1)
    ctxPeer.InsertTxHeader(i, &tx1)
}
```




