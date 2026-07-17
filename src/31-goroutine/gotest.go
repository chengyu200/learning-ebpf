// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
package main

import (
	"fmt"
	"time"
)

func work(n int) {
	time.Sleep(10 * time.Millisecond)
	fmt.Println("done", n)
}

func main() {
	for i := 0; i < 10; i++ {
		go work(i)
	}
	time.Sleep(200 * time.Millisecond)
	fmt.Println("exit")
}
