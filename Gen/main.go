package main

import (
	"EBDL/RPC"
	Crypto "EBDL/cypto"
	"EBDL/transaction"
	"bytes"
	"encoding/binary"
	"fmt"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/rpcclient"
	"log"
	"math"
	"time"
)

var (
	miningAddr = "SXXfUx9qdszdhEgFJMq5625co9JrqbeRBv"
)

func main() {
	k := 3
	r := 3
	keyE := []byte("1234567890123456")
	keyL := []byte("1234567890123456")

	client := RPC.InitClient("127.0.0.1:28335", "simnet")
	// 解锁钱包
	err := client.WalletPassphrase("ts0", 6000)
	if err != nil {
		log.Fatal(err)
	}
	//message := Crypto.GenerateRandomContent(50000)
	message := "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"
	// 将message分为n块（每个交易的OP_RETURN最多可以保存80字节，但是保存的数据越大隐蔽性越差，因此选择与我们方案相同的32字节进行分块）
	n := (len(message) + 31) / 32
	var M []string
	for i := 0; i < len(message); i += 32 {
		if i+32 >= len(message) {
			m := message[i:]
			M = append(M, m)
			break
		}
		m := message[i : i+32]
		M = append(M, m)
	}
	//fmt.Println(M)

	S := MsgSeg(n, M, keyE)

	SpecTxGen(client, k, n, r, S, keyL)

	filterTx, _ := SpecTxScan(client, k, r, keyL)
	m, _ := MsgExtract(client, k, r, filterTx, keyE, keyL)
	fmt.Println(string(m[0]))
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

// SpecTxGen 在m前添加tag将tag||m嵌入OP_RETURN
func SpecTxGen(client *rpcclient.Client, k, n, r int, S [][]byte, keyL []byte) []*chainhash.Hash {
	var ain, aout string
	//var scripts []string
	aoutAddr, _ := client.GetNewAddress("default")
	aout = aoutAddr.String()
	_, err := transaction.EntireSendTrans(client, miningAddr, aout, 1, nil)
	client.Generate(1)
	time.Sleep(50 * time.Millisecond)

	if err != nil {
		fmt.Println(err)
	}
	var covertTrans []*chainhash.Hash
	k2 := k - 1
	lambda := int(math.Pow(2, float64(k)))
	// 默认所有地址都使用挖矿地址
	for i := 0; i < n; i++ {
		// 将前一次的输出地址作为本次的输入地址，循环使用utxo
		ain = aout
		// 生成下一个输出地址
		aoutAddr, _ = client.GetNewAddress("default")
		aout = aoutAddr.String()

		// 计算标签
		rou := xorStringWithInt(aout[:k2], r)
		l := rou + lambda/2 + 1
		tag, err := Crypto.Encrypt([]byte(ain), keyL)
		// 长度要求小于76，其中消息占48，标签需要小于28
		if l >= 28 {
			l = 27
		}
		tag = tag[:l]
		if err != nil {
			fmt.Println(err)
		}
		// 标签与密文合并
		D2 := append(tag, S[i]...)
		// 发送隐蔽交易
		T2, err := transaction.GenerateCovertTrans(client, ain, aout, D2)
		if err != nil {
			fmt.Println(err)
		}
		client.Generate(1)
		// 等待1s确保已经使用的utxo已经被记录，否则连续发送交易可能会使用同一个utxo
		time.Sleep(50 * time.Millisecond)
		if err != nil {
			fmt.Println(err)
		}
		// 保存脚本文件用于隐蔽性分析
		//script, err := transaction.GetOpReturnFromTrans(client, T2)
		//scripts = append(scripts, hex.EncodeToString(script))
		covertTrans = append(covertTrans, T2)
	}
	//fileoperator.SaveSignature(scripts, "OPRETURN_EBDL.xlsx")
	return covertTrans
}

// 在m前面添加seq、n后加密获得密文
func MsgSeg(n int, M []string, keyE []byte) [][]byte {
	// Algorithm1 MsgSeg
	seq := 1
	var S [][]byte
	for i := 0; i < n; i++ {
		// 将seq转为16比特2字节保存
		var seqByte [2]byte
		binary.BigEndian.PutUint16(seqByte[:], uint16(seq))
		// 将n转为8比特1字节保存
		var nByte byte
		nByte = byte(n)
		var m2 []byte
		m2 = append(append(append(m2, seqByte[:]...), nByte), []byte(M[i])...)
		ds, _ := Crypto.Encrypt((m2), keyE)
		S = append(S, ds)
		seq++
	}
	return S
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
