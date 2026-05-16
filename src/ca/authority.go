package ca

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"math/big"
	"time"

	cryptoutil "publickeyhandshake.com/public-key-handshake-assignment/src/crypto"
)

type Authority struct {
	privateKey     ed25519.PrivateKey
	publicKey      ed25519.PublicKey
	certificateDER []byte
	certificate    *x509.Certificate
}

func NewAuthority(commonName string) (*Authority, error) {
	if commonName == "" {return nil, errors.New("please enter CA common name")}

	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {return nil, fmt.Errorf("generate CA key pair: %w", err)}

	serialNumber, err := randomSerialNumber()
	if err != nil {return nil, fmt.Errorf("generate CA serial number: %w", err)}

	now := time.Now()
	certificateTemplate := &x509.Certificate{
		SerialNumber:          serialNumber,
		Subject:               pkix.Name{CommonName: commonName, Organization: []string{"public key handshake assignment"}},
		NotBefore:             now.Add(-1 * time.Hour),
		NotAfter:              now.AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            1,
	}

	certificateDER, err := x509.CreateCertificate(rand.Reader, certificateTemplate, certificateTemplate, publicKey, privateKey)
	if err != nil {return nil, fmt.Errorf("create CA certificate: %w", err)}

	certificate, err := x509.ParseCertificate(certificateDER)
	if err != nil {return nil, fmt.Errorf("parse CA certificate: %w", err)}

	return &Authority{privateKey: privateKey, publicKey: publicKey, certificateDER: certificateDER, certificate: certificate}, nil
}

func (authority *Authority) IssueServerCertificate(
	serverIdentity string,
	serverPublicKey ed25519.PublicKey,
) ([]byte, error) {
	if authority == nil {return nil, errors.New("authority is null")}
	if serverIdentity == "" {return nil, errors.New("please input server identity")}
	if len(serverPublicKey) != ed25519.PublicKeySize {return nil, errors.New("invalid server public key")}

	serialNumber, err := randomSerialNumber()
	if err != nil {return nil, fmt.Errorf("generate server certificate serial number: %w", err)}

	now := time.Now()
	serverTemplate := &x509.Certificate{
		SerialNumber:          serialNumber,
		Subject:               pkix.Name{CommonName: serverIdentity, Organization: []string{"public key handshare server"}},
		DNSNames:              []string{serverIdentity},
		NotBefore:             now.Add(-1 * time.Hour),
		NotAfter:              now.AddDate(1, 0, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  false,
	}

	serverCertificateDER, err := x509.CreateCertificate(
		rand.Reader,
		serverTemplate,
		authority.certificate,
		serverPublicKey,
		authority.privateKey,
	)
	if err != nil {return nil, fmt.Errorf("create server certificate: %w", err)}

	return serverCertificateDER, nil
}

func (authority *Authority) PublicKey() ed25519.PublicKey {
	if authority == nil {return nil}
	return append(ed25519.PublicKey(nil), authority.publicKey...)
}

func (authority *Authority) CertificateDER() []byte {
	if authority == nil {return nil}
	return cryptoutil.CloneBytes(authority.certificateDER)
}

func randomSerialNumber() (*big.Int, error) {
	return rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
}
