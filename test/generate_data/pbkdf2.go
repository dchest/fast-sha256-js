package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"

	"golang.org/x/crypto/pbkdf2"
)

func main() {
	var rs [128][3][]byte
	for i := range rs {
		p := make([]byte, i)
		if _, err := io.ReadFull(rand.Reader, p[:]); err != nil {
			panic(err)
		}
		s := make([]byte, i)
		if _, err := io.ReadFull(rand.Reader, s[:]); err != nil {
			panic(err)
		}
		c := 128 - i + 2
		dk := pbkdf2.Key(p, s, c, i+8, sha256.New)
		rs[i][0] = p
		rs[i][1] = s
		rs[i][2] = dk
	}
	out, err := json.MarshalIndent(rs, "", "")
	if err != nil {
		panic(err)
	}
	fmt.Print("module.exports = ")
	fmt.Print(string(out))
	fmt.Println(";")
}
