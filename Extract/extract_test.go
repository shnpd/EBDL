package main

import (
	"EBDL/RPC"
	"EBDL/transaction"
	"fmt"
	"github.com/btcsuite/btcd/btcjson"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"testing"
)

func TestExtract(t *testing.T) {
	client := RPC.InitClient("127.0.0.1:28334", "mainnet")

	txIdWithOpReturn := []string{"8a8410632187aaabae96984c034426294c7a159e7f3c2daebec9cfcca33ad79c",
		"f8ce52db3f2e5de3cd220e48191a8ea7068249d6428b7018944d34b11fc80a45",
		"84bb82cff0d66c07b10ba853ca90d6af6804726d9b71b9ec43f6c1d3cbef83b6",
		"4246dcdc2194fb5254658e551b7c109750edbefedd5040c3015fcce66f44e0c6",
		"ba7c0b27c08d575809f857ecb8e67a84b93d1bb5bf194e43db4e22241af476e4",
		"8785c682a15e9d6e1324a25c541051fe8ff34b8e8b92cdc664877aedf33cd93e",
		"b14579621ab950aaa7eb04bfaaecbde86b5ce632e0e70fdea11b4c8c28a59e45",
		"6031d7ab0114dffb85be4ccaf4c85b04e864e236911c972e36b4960554c83fb8",
		"efa4e4d3d79bcc7aea4b09214b57f0fb9917e15eb121fe5de21294f798fe3e81",
		"1331dd8fa702b471f461ad016754be113a79d7e49aa436dec9bc83e3288a62f4",
		"1c2235885d8ca636c52e4bc2ed96fdaebbdd335f964cfa4f2b90dd750b70b517",
		"2f95bbb8af96dcc45c99e7a74ecec608a7c31f1b35aacb7309fa2eaf754900df",
		"7e48ceb792a242d1d2c4fa77c1bab717b4f6daf0b3c61d2792b81d3ac39a0487",
		"4474da7b467aef27b824e9aaa11991e3f9542e81e127928d757246e5bf4ba1e0"}

	var txWithOpReturn []*btcjson.TxRawResult
	for _, txid := range txIdWithOpReturn {
		txhash, _ := chainhash.NewHashFromStr(txid)
		tx, _ := client.GetRawTransactionVerbose(txhash)
		txWithOpReturn = append(txWithOpReturn, tx)
	}

	for _, tx := range txWithOpReturn {
		s, _ := transaction.GetTxOpReturn(tx)
		fmt.Println(s)
	}
}
