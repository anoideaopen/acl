package proto

//go:generate protoc -I=. --go_out=. args.proto
//go:generate protoc -I=. --go_out=. acl-config.proto
