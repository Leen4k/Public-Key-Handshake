package cryptoutil

import (
	"bytes"
	"testing"
)

func TestBuildHandshakeTranscriptDeterministic(t *testing.T) {
	clientNonce := bytes.Repeat([]byte{0x11}, 32)
	serverNonce := bytes.Repeat([]byte{0x22}, 32)
	clientDHPublic := mustParseHexBigInt("123456789ABCDEF")
	serverDHPublic := mustParseHexBigInt("FEDCBA987654321")

	firstTranscript, err := BuildHandshakeTranscript(clientNonce, serverNonce, clientDHPublic, serverDHPublic)

	if err != nil {t.Fatalf("build first transcript: %v", err)}
	secondTranscript, err := BuildHandshakeTranscript(clientNonce, serverNonce, clientDHPublic, serverDHPublic)
	if err != nil {t.Fatalf("build second transcript: %v", err)}
	if !bytes.Equal(firstTranscript, secondTranscript) {t.Fatal("transcript encoding is not deterministic")}
}

func TestDHSharedSecretEquality(t *testing.T) {
	primeModulus, generator := DefaultDHParameters()

	clientDHPrivate, err := GenerateDHPrivateKey(primeModulus)
	if err != nil {t.Fatalf("generate client DH private key: %v", err)}
	serverDHPrivate, err := GenerateDHPrivateKey(primeModulus)
	if err != nil {t.Fatalf("generate server DH private key: %v", err)}

	clientDHPublic := ComputeDHPublicKey(generator, clientDHPrivate, primeModulus)
	serverDHPublic := ComputeDHPublicKey(generator, serverDHPrivate, primeModulus)

	clientSharedSecret := ComputeDHSharedSecret(serverDHPublic, clientDHPrivate, primeModulus)
	serverSharedSecret := ComputeDHSharedSecret(clientDHPublic, serverDHPrivate, primeModulus)

	if clientSharedSecret.Cmp(serverSharedSecret) != 0 {t.Fatal("client and server shared secrets are different")}
	if clientSharedSecret.Sign() <= 0 {t.Fatal("shared secret should be positive")}
}
