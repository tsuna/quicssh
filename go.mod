module github.com/tsuna/quicssh

go 1.25

require (
	github.com/quic-go/quic-go v0.59.0
	github.com/urfave/cli/v2 v2.27.7
	github.com/vishvananda/netlink v1.3.1
	golang.org/x/net v0.48.0
	golang.org/x/sys v0.41.0
)

require (
	github.com/cpuguy83/go-md2man/v2 v2.0.7 // indirect
	github.com/russross/blackfriday/v2 v2.1.0 // indirect
	github.com/vishvananda/netns v0.0.5 // indirect
	github.com/xrash/smetrics v0.0.0-20250705151800-55b8f293f342 // indirect
	golang.org/x/crypto v0.46.0 // indirect
)

replace github.com/quic-go/quic-go => github.com/tsuna/quic-go v0.0.0-20260302230228-b948471856a8
