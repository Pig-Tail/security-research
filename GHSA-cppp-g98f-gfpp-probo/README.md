# GHSA-cppp-g98f-gfpp — Probo ADMIN→OWNER vertical privilege escalation via createUser

- **Advisory:** [GHSA-cppp-g98f-gfpp](https://github.com/getprobo/probo/security/advisories/GHSA-cppp-g98f-gfpp) (no CVE assigned)
- **Affected:** getprobo/probo ≤ 0.222.2 · **Fixed:** 0.223.1
- **Severity:** High (CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H = 7.2) · **CWE-269** / **CWE-863**
- **Impact:** an organization **ADMIN** mints themselves (or anyone) an **OWNER** membership,
  bypassing the owner-only set-owner gate — gaining SSO/SAML config, SCIM, and org-deletion
  powers ADMIN is explicitly denied. Not GID-gated.

## Root cause

A policy asymmetry between two write paths for the same field (`membership.Role`):

- `createUser` (resolver + MCP `CreateUserTool`) authorizes only
  `iam:membership-profile:create` — which **ADMIN holds** — and forwards `input.Role`
  verbatim. `CreateUserRequest.Validate()` never restricts `Role`, and the service inserts
  `membership.Role = req.Role` unchanged.
- `updateMembership`, by contrast, gates `Role == OWNER` behind
  `iam:membership-role:set-owner` — which **ADMIN does not hold**.

So the guard that protects role elevation on the update path is simply absent on the create
path. ADMIN → `createUser(role: OWNER)` → OWNER.

## PoC

`poc/privesc_poc_test.go` uses the **real shipped IAM policy set and evaluator** (`pkg/iam`) to
prove the asymmetry: `iam:membership-role:set-owner` evaluates `deny` for ADMIN while the
create path never requires it. Run inside a probo checkout:

```sh
go test ./pkg/iam/ -run TestPrivescPoC_AdminCanSetOwnerViaCreateUser -v
```

> Note: `pkg/iam` tests need the generated `packages/emails/dist` template stubs to compile
> (normally npm-generated); create empty stubs to build, remove after.

## Fix

Validate `Role` on the create path against the same `set-owner` authorization the update path
enforces (reject OWNER unless the caller holds `iam:membership-role:set-owner`). Resolved in
probo 0.223.1.
