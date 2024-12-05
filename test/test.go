package main

import (
	"EBDL/RPC"
	"encoding/hex"
	"fmt"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/rpcclient"
)

func main() {
	client := RPC.InitClient("127.0.0.1:28334", "mainnet")
	txid := "6031d7ab0114dffb85be4ccaf4c85b04e864e236911c972e36b4960554c83fb8"
	txhash, _ := chainhash.NewHashFromStr(txid)
	txdetail, _ := client.GetRawTransactionVerbose(txhash)

	ver := txdetail.Vout[0].ScriptPubKey.Hex
	rawtrans, _ := client.GetRawTransaction(txhash)
	raw := rawtrans.MsgTx().TxOut[0].PkScript
	fmt.Println(ver)

	fmt.Println()
	fmt.Println(hex.EncodeToString(raw))

}

func test(t []int) {
	t = append(t, 1)
	fmt.Println(t)
}

// GetTransFromBlock 获取区块高度从hb到he的所有交易
func GetTransFromBlock(client *rpcclient.Client, hb, he int64) []*chainhash.Hash {
	var txids []*chainhash.Hash
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
			txids = append(txids, txid)
		}
	}
	return txids
}

// 获取交易的第一个输入地址和第一个输出地址(遍历所有地址时间开销过大,筛选100个区块需要30分钟)
func getTransAddr(client *rpcclient.Client, txHash *chainhash.Hash) (string, string) {
	client.GetRawTransactionVerbose(txHash)
	//client.GetRawTransaction(txHash)
	//
	//if err != nil {
	//	log.Fatalf("Error fetching transaction: %v", err)
	//}
	//// 遍历交易输入，解析地址
	//vin := txDetails.Vin[0]
	// 获取输入的交易输出索引信息
	//prevTxid := vin.Txid
	//// 输入交易为空则跳过（初始交易）
	//if prevTxid == "" {
	//	return "", ""
	//}
	//voutIndex := vin.Vout
	//// 查询前一个交易的输出
	//hash, _ := chainhash.NewHashFromStr(prevTxid)
	//client.GetRawTransactionVerbose(hash)
	//if err != nil {
	//	log.Fatalf("Error fetching previous transaction: %v", err)
	//}
	//// 获取指定输出的地址
	//vout := prevTx.Vout[voutIndex]
	//address := vout.ScriptPubKey.Address
	//if address != "" {
	//	ain = address
	//}
	//
	//vout2 := txDetails.Vout[0]
	//if vout2.ScriptPubKey.Address != "" {
	//	aout = vout2.ScriptPubKey.Address
	//}
	return "", ""
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
