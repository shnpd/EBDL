package main

import (
	"fmt"
)

func main() {
	t := make([]int, 3, 10)
	test(t)
	fmt.Println(t)

	newt := t[0:4]
	fmt.Println(newt)
	//[0 0 0 1]
	//[0 0 0]
	//[0 0 0 1]
}

func test(t []int) {
	t = append(t, 1)
	fmt.Println(t)
}
