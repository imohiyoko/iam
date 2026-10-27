module github.com/imohiyoko/iam/adapters/ephemeral/redis

go 1.27.0

require (
	github.com/imohiyoko/iam v0.0.0
	github.com/redis/go-redis/v9 v9.22.0
)

require (
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	go.uber.org/atomic v1.11.0 // indirect
	golang.org/x/sys v0.48.0 // indirect
)

replace github.com/imohiyoko/iam => ../../..
