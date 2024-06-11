package main

import (
	"log"

	acl "github.com/anoideaopen/acl/cc"
)

func main() {
	cc, err := acl.New()
	if err != nil {
		log.Fatal(err)
	}

	if err = cc.Start(); err != nil {
		log.Fatal(err)
	}
}
