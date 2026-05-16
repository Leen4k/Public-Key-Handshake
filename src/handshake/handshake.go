package handshake

import (
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"math/big"
	"strings"

	"publickeyhandshake.com/public-key-handshake-assignment/src/ca"
	"publickeyhandshake.com/public-key-handshake-assignment/src/client"
	cryptoutil "publickeyhandshake.com/public-key-handshake-assignment/src/crypto"
	"publickeyhandshake.com/public-key-handshake-assignment/src/protocol"
	"publickeyhandshake.com/public-key-handshake-assignment/src/server"
)

const serverIdentity = "example.com"

type ScenarioResult struct {
	Name    string
	Success bool
	Details string
}

func RunAllScenarios() []ScenarioResult {
	return []ScenarioResult{runNormalHandshake(), runTamperedServerDHPublic(), runFakeCertificate(), runTamperedTranscriptBeforeFinished()}
}

func runNormalHandshake() ScenarioResult {
	trustedCA, err := ca.NewAuthority("trusted course CA")
	if err != nil {return failedScenario("normal handshake success", err)}

	handshakeClient, handshakeServer, _, err := setupClientAndServer(trustedCA, trustedCA)
	if err != nil {return failedScenario("normal handshake success", err)}

	if err := completeHandshake(handshakeClient, handshakeServer); err != nil {return failedScenario("normal handshake success", err)}
	if !handshakeServer.SessionEstablished() {return ScenarioResult{Name: "normal handshake success", Success: false, Details: "session was not marked established"}}

	return ScenarioResult{Name: "normal handshake success", Success: true, Details: "client and server completed authenticated key exchange"}
}

func runTamperedServerDHPublic() ScenarioResult {
	trustedCA, err := ca.NewAuthority("trusted course CA")
	if err != nil {return failedScenario("tampered server DH public rejected", err)}
	handshakeClient, handshakeServer, primeModulus, err := setupClientAndServer(trustedCA, trustedCA)

	if err != nil {return failedScenario("tampered server DH public rejected", err)}
	clientHello, err := handshakeClient.StartHandshake()

	if err != nil {return failedScenario("tampered server DH public rejected", err)}
	serverHello, err := handshakeServer.HandleClientHello(clientHello)

	if err != nil {return failedScenario("tampered server DH public rejected", err)}
	serverHello.ServerDHPublic = nextValidDHPublicValue(serverHello.ServerDHPublic, primeModulus)

	_, err = handshakeClient.HandleServerHello(serverHello)
	if err == nil {return ScenarioResult{Name: "tampered server DH public rejected", Success: false, Details: "tampered DH value unexpectedly passed verification"}}
	if !strings.Contains(err.Error(), "server handshake signature verification") {return ScenarioResult{Name: "tampered server DH public rejected", Success: false, Details: fmt.Sprintf("expected signature verification failure, got: %v", err)}}

	return ScenarioResult{Name: "tampered server DH public rejected", Success: true, Details: "client rejected modified server ephemeral key via signature check"}
}

func runFakeCertificate() ScenarioResult {
	trustedCA, err := ca.NewAuthority("trusted course CA")
	if err != nil {return failedScenario("fake certificate rejected", err)}
	fakeCA, err := ca.NewAuthority("Mallory Fake CA")

	if err != nil {return failedScenario("fake certificate rejected", err)}

	handshakeClient, handshakeServer, _, err := setupClientAndServer(trustedCA, fakeCA)
	if err != nil {return failedScenario("fake certificate rejected", err)}
	clientHello, err := handshakeClient.StartHandshake()

	if err != nil {return failedScenario("fake certificate rejected", err)}
	serverHello, err := handshakeServer.HandleClientHello(clientHello)

	if err != nil {return failedScenario("fake certificate rejected", err)}
	_, err = handshakeClient.HandleServerHello(serverHello)

	if err == nil {return ScenarioResult{Name: "fake certificate rejected", Success: false, Details: "fake certificate unexpectedly passed validation"}}
	if !strings.Contains(err.Error(), "certificate signature verification failed") {return ScenarioResult{Name: "fake certificate rejected", Success: false, Details: fmt.Sprintf("expected certificate verification failure, got: %v", err)}}

	return ScenarioResult{Name: "fake certificate rejected", Success: true, Details: "client rejected certificate not signed by trusted CA"}
}

func runTamperedTranscriptBeforeFinished() ScenarioResult {
	trustedCA, err := ca.NewAuthority("trusted course CA")

	if err != nil {return failedScenario("transcript tamper that cause MAC failure", err)}
	handshakeClient, handshakeServer, _, err := setupClientAndServer(trustedCA, trustedCA)

	if err != nil {return failedScenario("transcript tamper that cause MAC failure", err)}

	clientFinished, err := runUntilClientFinished(handshakeClient, handshakeServer)
	if err != nil {return failedScenario("transcript tamper that cause MAC failure", err)}

	if len(clientFinished.ClientHandshakeMAC) == 0 {return ScenarioResult{Name: "transcript tamper that cause MAC failure", Success: false, Details: "client produce empty handshake MAC"}}

	clientFinished.ClientHandshakeMAC[0] ^= 0x01
	err = handshakeServer.HandleClientFinished(clientFinished)
	if err == nil {return ScenarioResult{Name: "transcript tamper that cause MAC failure", Success: false, Details: "tampered ClientFinished unexpectedly passed MAC verification"}}
	if !strings.Contains(err.Error(), "client handshake MAC verification failed") {return ScenarioResult{Name: "transcript tamper that cause MAC failure", Success: false, Details: fmt.Sprintf("expected MAC verification failure, got: %v", err)}}

	return ScenarioResult{Name: "transcript tamper that cause MAC failure", Success: true, Details: "server rejected tampered finished message by MAC mismatch"}
}

func setupClientAndServer(
	trustedCA *ca.Authority,
	certificateIssuer *ca.Authority,
) (*client.Client, *server.Server, *big.Int, error) {
	primeModulus, generator := cryptoutil.DefaultDHParameters()

	serverPublicKey, serverPrivateKey, err := ed25519.GenerateKey(rand.Reader)

	if err != nil {return nil, nil, nil, fmt.Errorf("generate server long-term key pair: %w", err)}
	serverCertificateDER, err := certificateIssuer.IssueServerCertificate(serverIdentity, serverPublicKey)

	if err != nil {return nil, nil, nil, fmt.Errorf("issue server certificate: %w", err)}

	handshakeServer, err := server.NewServer(server.ServerConfig{
		ServerCertificateDER: serverCertificateDER,
		ServerPrivateKey:     serverPrivateKey,
		PrimeModulus:         primeModulus,
		Generator:            generator,
	})

	if err != nil {return nil, nil, nil, fmt.Errorf("create server: %w", err)}

	handshakeClient, err := client.NewClient(client.ClientConfig{
		TrustedCAPublicKey:     trustedCA.PublicKey(),
		ExpectedServerIdentity: serverIdentity,
		PrimeModulus:           primeModulus,
		Generator:              generator,
	})

	if err != nil {return nil, nil, nil, fmt.Errorf("create client: %w", err)}

	return handshakeClient, handshakeServer, primeModulus, nil
}

func completeHandshake(
	handshakeClient *client.Client,
	handshakeServer *server.Server,
) error {
	clientFinished, err := runUntilClientFinished(handshakeClient, handshakeServer)

	if err != nil {return err}
	if err := handshakeServer.HandleClientFinished(clientFinished); err != nil {return fmt.Errorf("server rejected ClientFinished: %w", err)}

	return nil
}

func runUntilClientFinished(
	handshakeClient *client.Client,
	handshakeServer *server.Server,
) (protocol.ClientFinished, error) {
	clientHello, err := handshakeClient.StartHandshake()
	if err != nil {return protocol.ClientFinished{}, fmt.Errorf("client start handshake: %w", err)}
	serverHello, err := handshakeServer.HandleClientHello(clientHello)

	if err != nil {return protocol.ClientFinished{}, fmt.Errorf("server handle ClientHello: %w", err)}
	clientFinished, err := handshakeClient.HandleServerHello(serverHello)

	if err != nil {return protocol.ClientFinished{}, fmt.Errorf("client handle ServerHello: %w", err)}

	return clientFinished, nil
}

func nextValidDHPublicValue(original *big.Int, primeModulus *big.Int) *big.Int {

	if original == nil {return big.NewInt(2)}
	upperBound := new(big.Int).Sub(primeModulus, big.NewInt(2))
	candidate := new(big.Int).Add(original, big.NewInt(1))
	if candidate.Cmp(upperBound) > 0 {candidate = new(big.Int).Sub(original, big.NewInt(1))}
	if candidate.Cmp(big.NewInt(2)) < 0 {candidate = big.NewInt(2)}

	return candidate
}

func failedScenario(name string, err error) ScenarioResult {
	return ScenarioResult{Name: name, Success: false, Details: err.Error()}
}
