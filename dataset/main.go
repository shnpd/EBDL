package main

import (
	"encoding/hex"
	"fmt"
	"github.com/xuri/excelize/v2"
)

// 统计交易输出脚本中OP_RETURN为空的占比
func main() {
	f, err := excelize.OpenFile("dataSet/OP_RETURN.xlsx")
	if err != nil {
		panic(err)
	}
	lengthCnt := make(map[int]int)
	cols, _ := f.GetCols("sheet1")
	emptyCnt := 0
	col := cols[0]
	for _, s := range col {
		if s == "empty" {
			emptyCnt++
		} else {
			sByte, _ := hex.DecodeString(s)
			lengthCnt[len(sByte)]++
			if len(sByte) == 83 {
				fmt.Println(sByte)
			}
		}

	}
	percent := float64(emptyCnt) / float64(len(col))
	fmt.Println(percent)

	fmt.Println(lengthCnt)
}
