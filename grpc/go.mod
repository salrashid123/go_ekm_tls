module main

go 1.26.2

require (
	github.com/salrashid123/ekmcredential v0.0.0-00010101000000-000000000000
	github.com/salrashid123/example/echo v0.0.0
	google.golang.org/grpc v1.80.0
)

require (
	golang.org/x/net v0.53.0 // indirect
	golang.org/x/sys v0.43.0 // indirect
	golang.org/x/text v0.36.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20260420184626-e10c466a9529 // indirect
	google.golang.org/protobuf v1.36.11 // indirect
)

replace (
	github.com/salrashid123/ekmcredential => ./ekm
	github.com/salrashid123/example/echo => ./echo
)
