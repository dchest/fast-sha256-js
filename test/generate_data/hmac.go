package main

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
)

func main() {
	var rs [1070][3][]byte
	for i := range rs {
		m := make([]byte, i)
		if _, err := io.ReadFull(rand.Reader, m[:]); err != nil {
			panic(err)
		}
		k := make([]byte, i/2)
		if _, err := io.ReadFull(rand.Reader, k[:]); err != nil {
			panic(err)
		}
		mac := hmac.New(sha256.New, k)
		mac.Write(m)
		h := mac.Sum(nil)
		rs[i][0] = m
		rs[i][1] = k
		rs[i][2] = h[:]
	}
	out, err := json.MarshalIndent(rs, "", "")
	if err != nil {
		panic(err)
	}
	fmt.Print("module.exports = ")
	fmt.Print(string(out))
	fmt.Println(";")
}
