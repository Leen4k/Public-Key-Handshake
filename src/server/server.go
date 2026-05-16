package server

import (
	"bytes"
	"crypto/ed25519"
	"crypto/x509"
	"errors"
	"fmt"
	"math/big"

	cryptoutil "publickeyhandshake.com/public-key-handshake-assignment/src/crypto"
	"publickeyhandshake.com/public-key-handshake-assignment/src/protocol"
)

type ServerConfig struct {
	ServerCertificateDER []byte
	ServerPrivateKey     ed25519.PrivateKey
	PrimeModulus         *big.Int
	Generator            *big.Int
}

type Server struct {
	config             ServerConfig
	pending            *pendingHandshake
	sessionEstablished bool
}

type pendingHandshake struct {
	clientNonce    []byte
	serverNonce    []byte
	transcriptHash []byte
	handshakeKey   []byte
}

func NewServer(config ServerConfig) (*Server, error) {

	if len(config.ServerCertificateDER) == 0 {return nil, errors.New("server certificate is required")}
	if len(config.ServerPrivateKey) != ed25519.PrivateKeySize {return nil, errors.New("server private key is invalid")}
	if config.PrimeModulus == nil || config.PrimeModulus.Sign() <= 0 {return nil, errors.New("prime modulus is required")}
	if config.Generator == nil || config.Generator.Sign() <= 0 {return nil, errors.New("generator is required")}

	certificate, err := x509.ParseCertificate(config.ServerCertificateDER)
	
	if err != nil {return nil, fmt.Errorf("parse server certificate: %w", err)}
	certificatePublicKey, ok := certificate.PublicKey.(ed25519.PublicKey)
	if !ok {return nil, errors.New("server certificate does not contain an Ed25519 key")}
	privateKeyPublic := config.ServerPrivateKey.Public().(ed25519.PublicKey)
	if !bytes.Equal(certificatePublicKey, privateKeyPublic) {return nil, errors.New("server private key does not match certificate public key")}

	return &Server{config: ServerConfig{ServerCertificateDER: cryptoutil.CloneBytes(config.ServerCertificateDER), ServerPrivateKey: append(ed25519.PrivateKey(nil), config.ServerPrivateKey...), PrimeModulus: cryptoutil.CloneBigInt(config.PrimeModulus), Generator: cryptoutil.CloneBigInt(config.Generator)}}, nil
}

func (server *Server) HandleClientHello(clientHello protocol.ClientHello) (protocol.ServerHello, error) {
	server.sessionEstablished = false

	if len(clientHello.ClientNonce) != protocol.NonceSize {return protocol.ServerHello{}, errors.New("invalid client nonce length")}
	if err := cryptoutil.CheckDHPublicKey(clientHello.ClientDHPublic, server.config.PrimeModulus); err != nil {return protocol.ServerHello{}, fmt.Errorf("invalid client DH public value: %w", err)}

	serverNonce, err := cryptoutil.RandomBytes(protocol.NonceSize)
	if err != nil {return protocol.ServerHello{}, fmt.Errorf("generate server nonce: %w", err)}
	serverDHPrivate, err := cryptoutil.GenerateDHPrivateKey(server.config.PrimeModulus)
	if err != nil {return protocol.ServerHello{}, fmt.Errorf("generate server DH private key: %w", err)}
	serverDHPublic := cryptoutil.ComputeDHPublicKey(server.config.Generator, serverDHPrivate, server.config.PrimeModulus)

	transcript, err := cryptoutil.BuildHandshakeTranscript(
		clientHello.ClientNonce,
		serverNonce,
		clientHello.ClientDHPublic,
		serverDHPublic,
	)
	if err != nil {return protocol.ServerHello{}, fmt.Errorf("build transcript: %w", err)}
	transcriptHash := cryptoutil.HashSHA256(transcript)

	serverHandshakeSignature := ed25519.Sign(server.config.ServerPrivateKey, transcriptHash)
	sharedSecret := cryptoutil.ComputeDHSharedSecret(clientHello.ClientDHPublic, serverDHPrivate, server.config.PrimeModulus)
	handshakeKey, err := cryptoutil.DeriveHandshakeKey(sharedSecret, clientHello.ClientNonce, serverNonce)
	if err != nil {return protocol.ServerHello{}, fmt.Errorf("derive handshake key: %w", err)}

	server.pending = &pendingHandshake{
		clientNonce:    cryptoutil.CloneBytes(clientHello.ClientNonce),
		serverNonce:    cryptoutil.CloneBytes(serverNonce),
		transcriptHash: transcriptHash,
		handshakeKey:   handshakeKey,
	}

	return protocol.ServerHello{ServerNonce: cryptoutil.CloneBytes(serverNonce), ServerDHPublic: cryptoutil.CloneBigInt(serverDHPublic), ServerCertificateDER: cryptoutil.CloneBytes(server.config.ServerCertificateDER), ServerHandshakeSignature: cryptoutil.CloneBytes(serverHandshakeSignature)}, nil
}

func (server *Server) HandleClientFinished(clientFinished protocol.ClientFinished) error {

	if server.pending == nil {return errors.New("no active handshake to finalize")}
	expectedMAC := cryptoutil.ComputeHMACSHA256(server.pending.handshakeKey, server.pending.transcriptHash)
	if !cryptoutil.ConstantTimeEqual(expectedMAC, clientFinished.ClientHandshakeMAC) {return errors.New("client handshake MAC verification failed")}

	server.pending = nil
	server.sessionEstablished = true
	return nil
}

func (server *Server) SessionEstablished() bool {
	return server.sessionEstablished
}
