package main

import (
	"fmt"
)

func main() {
	v := createMD5Hasher()
	digest := v.getHash([]byte("Test string"))
	fmt.Printf("%v", digest)
}
