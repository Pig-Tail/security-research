package iam

// PoC (benign) for PROBO-PRIVESC-001: ADMIN -> OWNER vertical privilege escalation
// via createUser. The createUser resolver authorizes ONLY iam:membership-profile:create
// (which ADMIN holds) and passes input.Role verbatim to a Membership insert, with no
// role validation (CreateUserRequest.Validate never checks Role). The updateMembership
// resolver, by contrast, gates Role==OWNER behind iam:membership-role:set-owner (which
// ADMIN does NOT hold). This test proves the policy asymmetry that makes the escalation
// possible, using the REAL shipped IAM policies and evaluator.
//
// Run: go test ./pkg/iam/ -run TestPrivescPoC_AdminCanSetOwnerViaCreateUser -v

import (
	"testing"

	"github.com/stretchr/testify/require"
	"go.probo.inc/probo/pkg/iam/policy"
)

func evalRole(t *testing.T, role, action string) policy.Decision {
	t.Helper()
	ps := IAMPolicySet()
	policies := ps.RolePolicies[role]
	require.NotEmpty(t, policies, "expected policies for role %s", role)
	res := policy.NewEvaluator().Evaluate(
		policy.AuthorizationRequest{
			Action: action,
			ConditionContext: policy.ConditionContext{
				// Real scenario: an ADMIN acting inside their OWN org (createUser targets
				// input.OrganizationID = the admin's org), so principal.org == resource.org.
				Principal: map[string]string{"id": "u", "organization_id": "org_A"},
				Resource:  map[string]string{"id": "r", "organization_id": "org_A"},
			},
		},
		policies,
	)
	return res.Decision
}

func TestPrivescPoC_AdminCanSetOwnerViaCreateUser(t *testing.T) {
	const (
		actCreate   = ActionMembershipProfileCreate // gate checked by createUser
		actSetOwner = ActionMembershipRoleSetOwner  // gate checked by updateMembership (Role==OWNER)
	)

	// 1. ADMIN is DENIED the set-owner action → cannot promote to OWNER via updateMembership.
	adminSetOwner := evalRole(t, "ADMIN", actSetOwner)
	require.NotEqual(t, policy.DecisionAllow, adminSetOwner,
		"ADMIN must NOT be allowed %s (the gate updateMembership enforces)", actSetOwner)

	// 2. ADMIN IS ALLOWED the create action → passes the ONLY gate createUser checks.
	adminCreate := evalRole(t, "ADMIN", actCreate)
	require.Equal(t, policy.DecisionAllow, adminCreate,
		"ADMIN is allowed %s, the only authz gate on createUser", actCreate)

	// 3. OWNER holds set-owner (sanity: it is genuinely an owner-only capability).
	require.Equal(t, policy.DecisionAllow, evalRole(t, "OWNER", actSetOwner),
		"OWNER holds set-owner (confirms it is a real privilege boundary)")

	// Conclusion: createUser authorizes only %s, and CreateUserRequest.Validate() never
	// restricts Role, and the service inserts membership.Role = req.Role verbatim. So an
	// ADMIN can call createUser(role=OWNER) and mint an OWNER membership, bypassing the
	// set-owner gate that updateMembership correctly enforces.
	t.Logf("PRIVESC CONFIRMED: ADMIN denied %s but allowed %s => createUser(role=OWNER) bypasses the owner gate.",
		actSetOwner, actCreate)
}
