# GHSA-j2p5-vc4m-xxhx — OpenCTI: read-only KNOWLEDGE user can delete other users' draft workspaces

- **Advisory:** [GHSA-j2p5-vc4m-xxhx](https://github.com/OpenCTI-Platform/opencti/security/advisories/GHSA-j2p5-vc4m-xxhx)
- **Severity:** Medium — CVSS 3.1 `AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N` (6.5) · CWE-285 / CWE-269 — no CVE assigned
- **Affected:** `opencti` (npm) `< 7.260604.0` · **Patched:** `7.260604.0`
- **Status:** publicly disclosed and fixed. Reported by **Pig-Tail** through coordinated disclosure.

## Summary

The GraphQL mutation `draftWorkspaceDelete` is guarded by `@auth(for: [KNOWLEDGE])` — the basic
**read** capability granted to the default user role. Combined with the default behaviour of
`getUserAccessRight`, any authenticated low-privilege user can delete draft workspaces created by
other users, without holding `KNOWLEDGE_KNUPDATE`, `KNOWLEDGE_KNUPDATE_KNDELETE`, or any
administrative capability.

## Root cause

Two defaults line up, and either one alone would be harmless:

1. **The `@auth` directive is too weak.** Every other mutation in the draft workspace module
   requires `KNOWLEDGE_KNUPDATE` or stronger; `draftWorkspaceDelete` checks only for `KNOWLEDGE`.
   The authorization model is right everywhere except this one entry point — which is why reading
   the module as a whole does not reveal it.
2. **The object-level check defaults open.** During the deletion flow, when `restricted_members` is
   empty on a draft workspace — the default state when drafts are created — access right resolution
   falls back to *administrative* access for all users. So the per-object guard that would have
   caught the weak directive instead waves it through.

A read capability plus an open-by-default object ACL adds up to a delete primitive.

## Impact

- Irreversible deletion of draft workspaces belonging to other users, taking with them the
  associated draft files, draft entities, draft relationships and worker/task draft context.
- Data loss and denial of service for analyst investigations — destructive rather than
  confidentiality-affecting, hence `C:N/I:H`.
- No confidentiality impact beyond the read access the attacker already has on draft metadata.

## Fix

Fixed in `7.260604.0` by restricting the mutation to the appropriate delete capabilities and
ensuring proper default member restrictions — both halves, not just the directive.

> **Write-up only.** No PoC is published here. The exploit is a single `draftWorkspaceDelete`
> GraphQL mutation issued with a default-role session against another user's draft, and it is
> irreversibly destructive to real analyst work: a runnable harness would be a data-destruction
> tool with no verification value a code review of the directive does not already give you.
