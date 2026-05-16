package client

import (
	"crypto/ed25519"
	"crypto/x509"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"time"

	cryptoutil "publickeyhandshake.com/public-key-handshake-assignment/src/crypto"
	"publickeyhandshake.com/public-key-handshake-assignment/src/protocol"
)

type ClientConfig struct {
	TrustedCAPublicKey     ed25519.PublicKey
	ExpectedServerIdentity string
	PrimeModulus           *big.Int
	Generator              *big.Int
}

type Client struct {
	config  ClientConfig
	pending *pendingHandshake
}

type pendingHandshake struct {
	clientNonce     []byte
	clientDHPrivate *big.Int
	clientDHPublic  *big.Int
}

func NewClient(config ClientConfig) (*Client, error) {
	if len(config.TrustedCAPublicKey) != ed25519.PublicKeySize {return nil, errors.New("trusted CA public key is invalid")}
	if config.ExpectedServerIdentity == "" {return nil, errors.New("expected server identity is required")}
	if config.PrimeModulus == nil || config.PrimeModulus.Sign() <= 0 {return nil, errors.New("prime modulus is required")}
	if config.Generator == nil || config.Generator.Sign() <= 0 {return nil, errors.New("generator is required")}

	return &Client{config: ClientConfig{TrustedCAPublicKey: append(ed25519.PublicKey(nil), config.TrustedCAPublicKey...), ExpectedServerIdentity: config.ExpectedServerIdentity, PrimeModulus: cryptoutil.CloneBigInt(config.PrimeModulus), Generator: cryptoutil.CloneBigInt(config.Generator)}}, nil
}

func (client *Client) StartHandshake() (protocol.ClientHello, error) {
	clientNonce, err := cryptoutil.RandomBytes(protocol.NonceSize)
	if err != nil {return protocol.ClientHello{}, fmt.Errorf("generate client nonce: %w", err)}

	clientDHPrivate, err := cryptoutil.GenerateDHPrivateKey(client.config.PrimeModulus)
	if err != nil {return protocol.ClientHello{}, fmt.Errorf("generate client DH private key: %w", err)}
	clientDHPublic := cryptoutil.ComputeDHPublicKey(client.config.Generator, clientDHPrivate, client.config.PrimeModulus)

	client.pending = &pendingHandshake{
		clientNonce:     clientNonce,
		clientDHPrivate: clientDHPrivate,
		clientDHPublic:  clientDHPublic,
	}

	return protocol.ClientHello{ClientNonce: cryptoutil.CloneBytes(clientNonce), ClientDHPublic: cryptoutil.CloneBigInt(clientDHPublic)}, nil
}

func (client *Client) HandleServerHello(serverHello protocol.ServerHello) (protocol.ClientFinished, error) {
	if client.pending == nil {return protocol.ClientFinished{}, errors.New("handshake not yet start..")}
	if len(serverHello.ServerNonce) != protocol.NonceSize {return protocol.ClientFinished{}, errors.New("invalid server nonce length")}
	if err := cryptoutil.CheckDHPublicKey(serverHello.ServerDHPublic, client.config.PrimeModulus); err != nil {return protocol.ClientFinished{}, fmt.Errorf("invalid server DH public value: %w", err)}

	serverCertificatePublicKey, err := verifyServerCertificate(
		serverHello.ServerCertificateDER,
		client.config.TrustedCAPublicKey,
		client.config.ExpectedServerIdentity,
	)
	if err != nil {return protocol.ClientFinished{}, err}

	transcript, err := cryptoutil.BuildHandshakeTranscript(
		client.pending.clientNonce,
		serverHello.ServerNonce,
		client.pending.clientDHPublic,
		serverHello.ServerDHPublic,
	)
	if err != nil {return protocol.ClientFinished{}, fmt.Errorf("build transcript: %w", err)}
	transcriptHash := cryptoutil.HashSHA256(transcript)

	if !ed25519.Verify(serverCertificatePublicKey, transcriptHash, serverHello.ServerHandshakeSignature) {return protocol.ClientFinished{}, errors.New("server handshake signature verification failed")}

	sharedSecret := cryptoutil.ComputeDHSharedSecret(serverHello.ServerDHPublic, client.pending.clientDHPrivate, client.config.PrimeModulus)
	handshakeKey, err := cryptoutil.DeriveHandshakeKey(sharedSecret, client.pending.clientNonce, serverHello.ServerNonce)
	if err != nil {return protocol.ClientFinished{}, fmt.Errorf("derive handshake key: %w", err)}

	clientHandshakeMAC := cryptoutil.ComputeHMACSHA256(handshakeKey, transcriptHash)
	client.pending = nil

	return protocol.ClientFinished{ClientHandshakeMAC: clientHandshakeMAC}, nil
}

func verifyServerCertificate(
	serverCertificateDER []byte,
	trustedCAPublicKey ed25519.PublicKey,
	expectedServerIdentity string,
) (ed25519.PublicKey, error) {
	certificate, err := x509.ParseCertificate(serverCertificateDER)
	if err != nil {return nil, fmt.Errorf("parse server certificate: %w", err)}
	if !ed25519.Verify(trustedCAPublicKey, certificate.RawTBSCertificate, certificate.Signature) {return nil, errors.New("certificate signature verification failed")}

	now := time.Now()
	if now.Before(certificate.NotBefore) || now.After(certificate.NotAfter) {return nil, errors.New("server certificate is not within validity period")}
	if !certificateIdentityMatches(certificate, expectedServerIdentity) {return nil, errors.New("server identity does not match certificate")}

	serverPublicKey, ok := certificate.PublicKey.(ed25519.PublicKey)
	if !ok {return nil, errors.New("server certificate does not contain an Ed25519 key")}

	return append(ed25519.PublicKey(nil), serverPublicKey...), nil
}

func certificateIdentityMatches(certificate *x509.Certificate, expectedIdentity string) bool {
	if len(certificate.DNSNames) > 0 {
		for _, dnsName := range certificate.DNSNames {
			if strings.EqualFold(dnsName, expectedIdentity) {return true}
		}
		return false
	}

	return strings.EqualFold(certificate.Subject.CommonName, expectedIdentity)
}
