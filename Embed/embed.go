package main

import (
	"EBDL/RPC"
	Crypto "EBDL/cypto"
	"EBDL/preshare"
	"EBDL/transaction"
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

	client := RPC.InitClient("127.0.0.1:28335", "simnet")
	// 解锁钱包
	err := client.WalletPassphrase("ts0", 6000)
	if err != nil {
		log.Fatal(err)
	}
	// 循环五次测试时间
	for i := 0; i < 5; i++ {
		//message := Crypto.GenerateRandomContent(50000)
		start := time.Now()
		message := "111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111"
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
		// 消息分段
		S := MsgSeg(n, M, preshare.KeyE)
		// 特殊交易生成
		specTx := SpecTxGen(client, preshare.K, n, preshare.R, S, preshare.KeyL)
		//SpecTxGen(client, preshare.K, n, preshare.R, S, preshare.KeyL)
		if i == 0 {
			fmt.Println("隐蔽交易数：", len(specTx))
		}
		duration := time.Since(start)

		start2 := time.Now()
		for i := 0; i < len(specTx); i++ {
			time.Sleep(50 * time.Millisecond)
		}
		duration2 := time.Since(start2)
		fmt.Println(duration - duration2)

	}
}

// SpecTxGen 在m前添加tag将tag||m嵌入OP_RETURN
func SpecTxGen(client *rpcclient.Client, k, n, r int, S [][]byte, keyL []byte) []*chainhash.Hash {
	var ain, aout string
	var covertTrans []*chainhash.Hash
	k2 := k - 1
	lambda := int(math.Pow(2, float64(k)))
	// 默认所有地址都使用挖矿地址	(将前一次的输出地址作为本次的输入地址，循环使用utxo，需要等待前一个交易确认，存在额外的时间开销)
	ain = miningAddr
	aout = miningAddr
	for i := 0; i < n; i++ {
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
		if err != nil {
			fmt.Println(err)
		}
		covertTrans = append(covertTrans, T2)
		// 防止双花，等待交易确认，注意在最终计算时间时减去该部分
		time.Sleep(50 * time.Millisecond)
	}
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

// xorStringWithInt 将字符串的每个字符与整数进行异或，并返回最终的整数结果
func xorStringWithInt(str string, num int) int {
	result := num // 初始化结果为传入的整数
	for i := 0; i < len(str); i++ {
		// 取当前字符的字节值
		result ^= int(str[i]) // 对字符字节与当前结果进行按位异或
	}
	return result
}
