package cryptoutil

import (
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"math/big"
)

const HandshakeKeySize = 32

var (
	defaultPrimeModulus = mustParseHexBigInt(
		"FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1" +
		"29024E088A67CC74020BBEA63B139B22514A08798E3404DD" +
			"EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245" +
			"E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED" +
			"EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D" +
			"C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F" +
			"83655D23DCA3AD961C62F356208552BB9ED529077096966D" +
			"670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B" +
			"E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9" +
			"DE2BCBF6955817183995497CEA956AE515D2261898FA0510" +
			"15728E5A8AACAA68FFFFFFFFFFFFFFFF",
	)
	defaultGenerator = big.NewInt(2)
)

func DefaultDHParameters() (primeModulus *big.Int, generator *big.Int) {
	return new(big.Int).Set(defaultPrimeModulus), new(big.Int).Set(defaultGenerator)
}

func RandomBytes(length int) ([]byte, error) {
	if length <= 0 {return nil, errors.New("random byte length must be positive number")}

	value := make([]byte, length)
	if _, err := rand.Read(value); err != nil {return nil, err}
	return value, nil
}

func GenerateDHPrivateKey(primeModulus *big.Int) (*big.Int, error) {
	if primeModulus == nil || primeModulus.Sign() <= 0 {return nil, errors.New("invalid prime modulus")}
	maxOffset := new(big.Int).Sub(primeModulus, big.NewInt(3))

	if maxOffset.Sign() <= 0 {return nil, errors.New("prime modulus too small")}
	privateKey, err := rand.Int(rand.Reader, maxOffset)

	if err != nil {return nil, err}

	privateKey.Add(privateKey, big.NewInt(2))
	return privateKey, nil
}

func CheckDHPublicKey(publicKey *big.Int, primeModulus *big.Int) error {
	if publicKey == nil {return errors.New("DH public key not found")}
	if primeModulus == nil || primeModulus.Sign() <= 0 {return errors.New("error prime modulus is not correct")}

	minValue := big.NewInt(2)
	maxValue := new(big.Int).Sub(primeModulus, big.NewInt(2))
	if publicKey.Cmp(minValue) < 0 || publicKey.Cmp(maxValue) > 0 {return errors.New("incorrect DH public key range")}

	return nil
}

func ComputeDHPublicKey(generator *big.Int, privateKey *big.Int, primeModulus *big.Int) *big.Int {
	return new(big.Int).Exp(generator, privateKey, primeModulus)
}

func ComputeDHSharedSecret(peerPublicKey *big.Int, privateKey *big.Int, primeModulus *big.Int) *big.Int {
	return new(big.Int).Exp(peerPublicKey, privateKey, primeModulus)
}

func BuildHandshakeTranscript(
	clientNonce []byte,
	serverNonce []byte,
	clientDHPublic *big.Int,
	serverDHPublic *big.Int,
) ([]byte, error) {

	if len(clientNonce) == 0 {return nil, errors.New("missing client nonce")}
	if len(serverNonce) == 0 {return nil, errors.New("missing server nonce")}
	if clientDHPublic == nil {return nil, errors.New("missing client DH public value")}
	if serverDHPublic == nil {return nil, errors.New("missing server DH public value")}

	transcript := make([]byte, 0, 4+len(clientNonce)+4+len(serverNonce)+4+len(clientDHPublic.Bytes())+4+len(serverDHPublic.Bytes()))
	transcript = appendLengthPrefixed(transcript, clientNonce)
	transcript = appendLengthPrefixed(transcript, serverNonce)
	transcript = appendLengthPrefixed(transcript, clientDHPublic.Bytes())
	transcript = appendLengthPrefixed(transcript, serverDHPublic.Bytes())

	return transcript, nil
}

func HashSHA256(data []byte) []byte {
	sum := sha256.Sum256(data)
	hash := make([]byte, sha256.Size)
	copy(hash, sum[:])
	return hash
}

func DeriveHandshakeKey(sharedSecret *big.Int, clientNonce []byte, serverNonce []byte) ([]byte, error) {
	if sharedSecret == nil || sharedSecret.Sign() <= 0 {return nil, errors.New("invalid shared secret")}
	if len(clientNonce) == 0 || len(serverNonce) == 0 {return nil, errors.New("nonces are required for key derivation")}

	saltInput := make([]byte, 0, len(clientNonce)+len(serverNonce))
	saltInput = append(saltInput, clientNonce...)
	saltInput = append(saltInput, serverNonce...)
	salt := HashSHA256(saltInput)

	return hkdf.Key(sha256.New, sharedSecret.Bytes(), salt, "public-key-handshake-key", HandshakeKeySize)
}

func ComputeHMACSHA256(key []byte, data []byte) []byte {
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write(data)
	return mac.Sum(nil)
}

func ConstantTimeEqual(left []byte, right []byte) bool {
	return subtle.ConstantTimeCompare(left, right) == 1
}

func CloneBytes(input []byte) []byte {
	if input == nil {return nil}
	cloned := make([]byte, len(input))
	copy(cloned, input)
	return cloned
}

func CloneBigInt(value *big.Int) *big.Int {
	if value == nil {return nil}
	return new(big.Int).Set(value)
}

func appendLengthPrefixed(dst []byte, field []byte) []byte {
	var lengthBytes [4]byte
	binary.BigEndian.PutUint32(lengthBytes[:], uint32(len(field)))
	dst = append(dst, lengthBytes[:]...)
	dst = append(dst, field...)
	return dst
}

func mustParseHexBigInt(hexValue string) *big.Int {
	value, ok := new(big.Int).SetString(hexValue, 16)
	if !ok {panic("invalid DH prime constant")}
	return value
}
