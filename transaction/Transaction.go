package transaction

import (
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/btcsuite/btcd/btcjson"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/rpcclient"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"log"
)

// 提取交易的输出输出地址
func GetTxAddr(client *rpcclient.Client, tx *btcjson.TxRawResult) (string, string) {
	var ain, aout string
	// 遍历交易输入，解析地址
	for _, vin := range tx.Vin {
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

	for _, vout := range tx.Vout {
		if vout.ScriptPubKey.Address != "" {
			aout = vout.ScriptPubKey.Address
			break
		}
	}

	return ain, aout
}

// 提取交易的OP_RETURN脚本
func GetTxOpReturn(tx *btcjson.TxRawResult) ([]byte, error) {
	TxOut := tx.Vout
	for _, out := range TxOut {
		script, _ := hex.DecodeString(out.ScriptPubKey.Hex)
		if script[0] == txscript.OP_RETURN {
			return script, nil
		}
	}
	return nil, errors.New("transaction not have OP_RETURN")
}

// 创建sourceAddr发起的特殊交易，包含两个输出，一个输出为OP_RETURN脚本包含隐蔽消息，另一个输出为找零将金额再转回输入地址
func GenerateCovertTrans(client *rpcclient.Client, sourceAddr, destAddr string, message []byte) (*chainhash.Hash, error) {
	// 创建交易
	tx := wire.NewMsgTx(wire.TxVersion)
	// 构造输入
	// 筛选输入的UTXO
	var sourceUTXO btcjson.ListUnspentResult
	utxos, _ := client.ListUnspent()
	for i, utxo := range utxos {
		if utxo.Address == sourceAddr {
			sourceUTXO = utxo
			break
		}
		if i == len(utxos)-1 {
			return nil, fmt.Errorf("UTXO not found")
		}
	}
	hash, _ := chainhash.NewHashFromStr(sourceUTXO.TxID)
	outPoint := wire.NewOutPoint(hash, sourceUTXO.Vout)
	txIn := wire.NewTxIn(outPoint, nil, nil)
	tx.AddTxIn(txIn)

	// 脚本输出
	opReturnScript, err := txscript.NewScriptBuilder().AddOp(txscript.OP_RETURN).AddData(message).Script()
	if err != nil {
		return nil, err
	}
	txOut := wire.NewTxOut(0, opReturnScript)
	tx.AddTxOut(txOut)

	// 实际输出
	changeAddr, _ := btcutil.DecodeAddress(destAddr, &chaincfg.SimNetParams)
	changeScript, err := txscript.PayToAddrScript(changeAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to create change script: %v", err)
	}
	changeAmount := int64((sourceUTXO.Amount * btcutil.SatoshiPerBitcoin) - 1000) // 减去手续费
	txOut2 := wire.NewTxOut(changeAmount, changeScript)
	tx.AddTxOut(txOut2)

	//	签名交易
	signedTx, complete, err, _ := client.SignRawTransaction(tx, nil)
	if err != nil {
		return nil, fmt.Errorf("error signing transaction: %v", err)
	}
	if !complete {
		return nil, fmt.Errorf("transaction signing incomplete: %v", err)
	}

	//	广播交易
	txHash, err := client.SendRawTransaction(signedTx, false)
	if err != nil {
		return nil, fmt.Errorf("error sending transaction: %v", err)
	}
	return txHash, nil
}

// EntireSendTrans 完整交易发送，包括交易生成、交易签名、交易广播，最终返回广播的交易id
func EntireSendTrans(client *rpcclient.Client, sourceAddr, destAddr string, amount int64, embedMsg *[]byte) (*chainhash.Hash, error) {
	rawTx, err := GenerateTrans(client, sourceAddr, destAddr, amount)
	if err != nil {
		return nil, err
	}
	signTx, err := SignTrans(client, rawTx, embedMsg)
	if err != nil {
		return nil, err
	}
	transId, err := BroadTrans(client, signTx)
	if err != nil {
		return nil, err
	}
	return transId, nil
}

// GenerateTrans 生成sourceAddr到destAddr的原始交易
func GenerateTrans(client *rpcclient.Client, sourceAddr, destAddr string, amount int64) (*wire.MsgTx, error) {
	// 筛选源地址的UTXO
	utxos, _ := client.ListUnspent()
	var sourceUTXO btcjson.ListUnspentResult
	for i, utxo := range utxos {
		if utxo.Address == sourceAddr {
			sourceUTXO = utxo
			break
		}
		if i == len(utxos)-1 {
			return nil, fmt.Errorf("UTXO not found")
		}
	}

	// 构造输入
	var inputs []btcjson.TransactionInput
	inputs = append(inputs, btcjson.TransactionInput{
		Txid: sourceUTXO.TxID,
		Vout: sourceUTXO.Vout,
	})
	//	构造输出
	outAddr, err := btcutil.DecodeAddress(destAddr, &chaincfg.SimNetParams)
	if err != nil {
		return nil, err
	}
	outputs := map[btcutil.Address]btcutil.Amount{
		// 0.1BTC的手续费
		outAddr: btcutil.Amount((sourceUTXO.Amount - 0.1) * 1e8),
	}
	//	创建交易
	rawTx, err := client.CreateRawTransaction(inputs, outputs, nil)
	if err != nil {
		return nil, fmt.Errorf("CreateRawTransaction error:%s", err)
	}
	return rawTx, nil
}

// SignTrans 签名交易，嵌入秘密消息，并保存特殊q
func SignTrans(client *rpcclient.Client, rawTx *wire.MsgTx, embedMsg *[]byte) (*wire.MsgTx, error) {
	signedTx, complete, err, _ := client.SignRawTransaction(rawTx, embedMsg)
	if err != nil {
		return nil, fmt.Errorf("error signing transaction: %v", err)
	}
	if !complete {
		return nil, fmt.Errorf("transaction signing incomplete")
	}

	return signedTx, nil
}

// BroadTrans 广播交易
func BroadTrans(client *rpcclient.Client, signedTx *wire.MsgTx) (*chainhash.Hash, error) {
	txHash, err := client.SendRawTransaction(signedTx, false)
	if err != nil {
		return nil, fmt.Errorf("SendRawTransaction error: %v", err)
	}
	return txHash, nil
}
