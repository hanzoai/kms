package kmsclient

import (
	"net"
	"strconv"
	"testing"

	"github.com/luxfi/zap"
)

// TestZAP_APeerThatAgreesNoSessionGetsNothing pins the one property this
// client exists to keep: everything it carries is a secret, so it does not
// speak to a peer it has not agreed an X25519 + ML-KEM-768 session with.
//
// The peer here accepts the connection and answers nothing on the handshake
// opcode. That is what a peer too old to speak it looks like from this side,
// and it is also what an on-path adversary looks like — dropping one message
// is the whole downgrade, and the reward is every secret afterwards in the
// clear, in both directions.
//
// The other half of the property — that a session which agreed X25519 alone
// is refused too — is what makes the pair hybrid rather than merely modern,
// and it is enforced on the same dial. TestZAP_DialAndGetPut is its evidence:
// that round trip only completes because the peer agreed ML-KEM-768.
func TestZAP_APeerThatAgreesNoSessionGetsNothing(t *testing.T) {
	port := pickEphemeralPort(t)
	peer := zap.NewNode(zap.NodeConfig{
		NodeID:      "peer-that-will-not-agree",
		ServiceType: "_kms._tcp",
		Port:        port,
		NoDiscovery: true,
	})
	if err := peer.Start(); err != nil {
		t.Fatalf("start peer: %v", err)
	}
	defer peer.Stop()

	ident, err := NewIdentity(testZAPMnemonic, "hanzo/test-client")
	if err != nil {
		t.Fatalf("NewIdentity: %v", err)
	}
	defer ident.Wipe()

	c, err := New(Config{
		Endpoint:        "zap://" + net.JoinHostPort("127.0.0.1", strconv.Itoa(port)),
		Org:             "hanzo",
		Env:             "test",
		Identity:        ident,
		TransportNodeID: "test-client-transport",
	})
	if err == nil {
		_ = c.Close()
		t.Fatal("a usable client came back for a peer that agreed no session — every secret after this crosses in the clear")
	}
}
