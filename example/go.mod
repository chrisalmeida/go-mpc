module go-mpc-example

go 1.26.0

require (
	filippo.io/edwards25519 v1.2.0
	github.com/btcsuite/btcd/btcec/v2 v2.5.0
	github.com/chrisalmeida/go-mpc v0.0.0
	github.com/stretchr/testify v1.12.1
)

require (
	github.com/bytemare/secp256k1 v0.5.0 // indirect
	github.com/decred/dcrd/dcrec/secp256k1/v4 v4.4.1 // indirect
	go.yaml.in/yaml/v3 v3.0.5 // indirect
	golang.org/x/crypto v0.58.0 // indirect
	golang.org/x/sys v0.49.0 // indirect
)

replace github.com/chrisalmeida/go-mpc => ../
