package main

import (
	"log"

	acl "github.com/anoideaopen/acl/cc"
)

func main() {
	cc := acl.New()

	if err := cc.Start(); err != nil {
		log.Fatal(err)
	}
}
