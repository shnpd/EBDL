package main

import (
	"EBDL/RPC"
	Crypto "EBDL/cypto"
	"EBDL/preshare"
	"EBDL/transaction"
	"bytes"
	"encoding/binary"
	"fmt"
	"github.com/btcsuite/btcd/btcjson"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/rpcclient"
	"math"
	"time"
)

func main() {
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

	// 解锁钱包
	//err := client.WalletPassphrase("ts0", 6000)
	//if err != nil {
	//	log.Fatal(err)
	//}
	for i := 0; i < 7; i++ {
		start := time.Now()
		filterTx, _ := SpecTxScan(client, preshare.K, preshare.R, preshare.KeyL)
		if i == 0 {
			filterTx = txWithOpReturn[:1]
		} else {
			filterTx = txWithOpReturn[:i*2]
		}
		m, _ := MsgExtract(client, preshare.K, preshare.R, filterTx, preshare.KeyE, preshare.KeyL)
		extractStr := ""
		for _, strm := range m {
			extractStr += string(strm)
		}
		duration := time.Since(start)
		fmt.Println(duration)
		fmt.Println(extractStr)
	}
}

func MsgExtract(client *rpcclient.Client, k, r int, filterTxs []*btcjson.TxRawResult, keyE, keyL []byte) ([][]byte, error) {
	k2 := k - 1
	lambda := int(math.Pow(2, float64(k)))
	seqm := make(map[int][]byte)
	for _, tx := range filterTxs {
		_, aout := transaction.GetTxAddr(client, tx)
		D, err := transaction.GetTxOpReturn(tx)
		if err != nil {
			return nil, err
		}
		D = D[2:]
		rou := xorStringWithInt(aout[:k2], r)
		l := rou + lambda/2 + 1
		// 长度要求小于76，其中消息占32，标签需要小于44
		if l >= 28 {
			l = 27
		}
		c := D[l:]
		decrypt, err := Crypto.Decrypt(c, keyE)
		if err != nil {
			return nil, err
		}
		seq := decrypt[:2]
		m := decrypt[3:]
		seqint := binary.BigEndian.Uint16(seq)
		seqm[int(seqint)] = m
	}
	var m [][]byte
	for i := 1; i <= len(seqm); i++ {
		m = append(m, seqm[i])
	}
	return m, nil
}

func SpecTxScan(client *rpcclient.Client, k int, r int, keyL []byte) ([]*btcjson.TxRawResult, error) {
	// Algorithm3 SpecTxScan
	// 获取待筛选交易
	k2 := k - 1
	lambda := int(math.Pow(2, float64(k)))
	var txs []*btcjson.TxRawResult
	var covertTxs []*btcjson.TxRawResult

	// 筛选最近100个区块的交易
	//latestBlock, _ := client.GetBlockCount()
	txs = GetTransFromBlock(client, 867100, 867199)
	// 筛选交易
	for _, tx := range txs {
		ain, aout := transaction.GetTxAddr(client, tx)
		if ain == "" || aout == "" {
			continue
		}
		D, err := transaction.GetTxOpReturn(tx)
		if err != nil {
			continue
		}
		// 嵌入的数据在加入op_return时会在头部加入1字节的op_return标志，以及长度标识，长度标识占用的字节与数据长度有关，76字节以下为1字节，我们嵌入的数据都为32字节，所以只需要去除1字节长度标识，从第2位起取出我们的嵌入内容
		if len(D) < 3 {
			continue
		}
		D = D[2:]
		rou := xorStringWithInt(aout[:k2], r)
		l := rou + lambda/2 + 1
		// 计算标签的长度，脚本长度要求小于76，其中消息占48，标签需要小于28
		if l >= 28 {
			l = 27
		}
		// 如果脚本长度小于标签长度直接跳过
		if len(D) < l {
			continue
		}
		tag, err := Crypto.Encrypt([]byte(ain), keyL)
		if err != nil {
			return nil, err
		}
		// 计算的标签
		tag = tag[:l]
		// 交易实际的标签

		tag2 := D[:l]
		if bytes.Equal(tag, tag2) {
			covertTxs = append(covertTxs, tx)
		}
	}
	return covertTxs, nil
}

// xorStringWithInt 将字符串的每个字符与整数进行异或，并返回最终的整数结果
func xorStringWithInt(str string, num int) int {
	result := num // 初始化结果为传入的整数
	for i := 0; i < len(str); i++ {
		// 取当前字符的字节值
		result ^= int(str[i]) // 对字符字节与当前结果进行按位异或
	}
	return result
}

// GetTransFromBlock 获取区块高度从hb到he的所有交易
func GetTransFromBlock(client *rpcclient.Client, hb, he int64) []*btcjson.TxRawResult {
	var txs []*btcjson.TxRawResult
	// 获取指定高度的区块哈希
	for height := hb; height <= he; height++ {
		blockHash, err := client.GetBlockHash(height)
		if err != nil {
			fmt.Printf("获取区块哈希失败 (高度: %d): %v\n", height, err)
		}
		block, err := client.GetBlockVerbose(blockHash)
		if err != nil {
			fmt.Printf("获取区块详情失败 (哈希: %s): %v\n", blockHash, err)
		}
		// 遍历区块中的每个交易
		for _, txID := range block.Tx {
			txid, _ := chainhash.NewHashFromStr(txID)
			txVer, _ := client.GetRawTransactionVerbose(txid)
			txs = append(txs, txVer)
		}
	}
	return txs
}
