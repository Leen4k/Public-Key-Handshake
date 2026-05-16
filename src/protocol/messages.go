package protocol

import "math/big"

const NonceSize = 32

type ClientHello struct {
	ClientNonce    []byte
	ClientDHPublic *big.Int
}

type ServerHello struct {
	ServerNonce              []byte
	ServerDHPublic           *big.Int
	ServerCertificateDER     []byte
	ServerHandshakeSignature []byte
}

type ClientFinished struct {
	ClientHandshakeMAC []byte
}
