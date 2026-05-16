package handshake
import "testing"

func TestNormalHandshakeScenario(t *testing.T) {
	result := runNormalHandshake()
	if !result.Success {t.Fatalf("%s: %s", result.Name, result.Details)}
}

func TestTamperedServerDHPublicScenario(t *testing.T) {
	result := runTamperedServerDHPublic()
	if !result.Success {t.Fatalf("%s: %s", result.Name, result.Details)}
}

func TestFakeCertificateScenario(t *testing.T) {
	result := runFakeCertificate()
	if !result.Success {t.Fatalf("%s: %s", result.Name, result.Details)}
}

func TestTranscriptTamperScenario(t *testing.T) {
	result := runTamperedTranscriptBeforeFinished()
	if !result.Success {t.Fatalf("%s: %s", result.Name, result.Details)}
}

func TestRunAllScenarios(t *testing.T) {
	results := RunAllScenarios()
	for _, result := range results {
		if !result.Success {t.Fatalf("%s: %s", result.Name, result.Details)}
	}
}
