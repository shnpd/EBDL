package main

import (
	"EBDL/RPC"
	Crypto "EBDL/cypto"
	"EBDL/preshare"
	"EBDL/transaction"
	"bytes"
	"encoding/binary"
	"fmt"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/rpcclient"
	"log"
	"math"
)

func main() {
	client := RPC.InitClient("127.0.0.1:28335", "simnet")
	// 解锁钱包
	err := client.WalletPassphrase("ts0", 6000)
	if err != nil {
		log.Fatal(err)
	}

	filterTx, _ := SpecTxScan(client, preshare.K, preshare.R, preshare.KeyL)
	m, _ := MsgExtract(client, preshare.K, preshare.R, filterTx, preshare.KeyE, preshare.KeyL)
	extractStr := ""
	for _, strm := range m {
		extractStr += string(strm)
	}
	fmt.Println(extractStr)
}

func MsgExtract(client *rpcclient.Client, k, r int, filterTxs []string, keyE, keyL []byte) ([][]byte, error) {
	k2 := k - 1
	lambda := int(math.Pow(2, float64(k)))
	seqm := make(map[int][]byte)
	for _, txid := range filterTxs {
		txhash, _ := chainhash.NewHashFromStr(txid)
		_, aout := getTransAddr(client, txhash)
		D, err := transaction.GetOpReturnFromTrans(client, txhash)
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

func SpecTxScan(client *rpcclient.Client, k int, r int, keyL []byte) ([]string, error) {
	// Algorithm3 SpecTxScan
	// 获取待筛选交易
	k2 := k - 1
	lambda := int(math.Pow(2, float64(k)))
	var txids []string
	var covertTxids []string
	transactions, err := client.ListTransactionsCount("*", 99999)
	if err != nil {
		return nil, err
	}
	// 保存交易id以便后续筛选
	for _, trans := range transactions {
		if trans.Generated {
			continue
		}
		if len(txids) == 0 {
			txids = append(txids, trans.TxID)
		} else if trans.TxID != txids[len(txids)-1] {
			txids = append(txids, trans.TxID)
		}
	}

	// 筛选交易
	for _, txid := range txids {
		hash, _ := chainhash.NewHashFromStr(txid)
		ain, aout := getTransAddr(client, hash)
		D, err := transaction.GetOpReturnFromTrans(client, hash)
		if err != nil {
			continue
		}
		// 嵌入的数据在加入op_return时会在头部加入1字节的op_return标志，以及长度标识，长度标识占用的字节与数据长度有关，76字节以下为1字节，我们嵌入的数据都为32字节，所以只需要去除1字节长度标识，从第2位起取出我们的嵌入内容
		D = D[2:]
		rou := xorStringWithInt(aout[:k2], r)
		l := rou + lambda/2 + 1
		// 如果脚本长度小于标签长度直接跳过
		// 长度要求小于76，其中消息占32，标签需要小于44
		if l >= 28 {
			l = 27
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
			covertTxids = append(covertTxids, txid)
		}
	}
	return covertTxids, nil
}
func getTransAddr(client *rpcclient.Client, txHash *chainhash.Hash) (string, string) {
	var ain, aout string
	txDetails, err := client.GetRawTransactionVerbose(txHash)
	if err != nil {
		log.Fatalf("Error fetching transaction: %v", err)
	}
	// 遍历交易输入，解析地址
	for _, vin := range txDetails.Vin {
		// 获取输入的交易输出索引信息
		prevTxid := vin.Txid
		// 输入交易为空则跳过（初始交易）
		if prevTxid == "" {
			return "", ""
		}
		voutIndex := vin.Vout
		// 查询前一个交易的输出
		hash, _ := chainhash.NewHashFromStr(prevTxid)
		prevTx, err := client.GetRawTransactionVerbose(hash)
		if err != nil {
			log.Fatalf("Error fetching previous transaction: %v", err)
		}
		// 获取指定输出的地址
		vout := prevTx.Vout[voutIndex]
		address := vout.ScriptPubKey.Address
		if address != "" {
			ain = address
			break
		}
	}

	for _, vout := range txDetails.Vout {
		if vout.ScriptPubKey.Address != "" {
			aout = vout.ScriptPubKey.Address
			break
		}
	}

	return ain, aout
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
