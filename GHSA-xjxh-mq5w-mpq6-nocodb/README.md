# GHSA-xjxh-mq5w-mpq6 — NocoDB: shared-view row filter skipped when a record is fetched by primary key

- **Advisory:** [GHSA-xjxh-mq5w-mpq6](https://github.com/nocodb/nocodb/security/advisories/GHSA-xjxh-mq5w-mpq6)
- **Severity:** High — CVSS 3.1 `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N` (7.5) · CWE-639 / CWE-863 — no CVE assigned
- **Affected:** NocoDB `< 2026.08.0` · **Patched:** `2026.08.0`
- **Status:** publicly disclosed and fixed. Reported by **Pig-Tail** through coordinated disclosure
  (first report; also reported independently by five other researchers).

## Summary

In NocoDB you can share a view through a public link. The view's row filter decides which
records the people with the link can see. The list and count endpoints applied that filter.
The public endpoints that open a single record by its primary key did not, so anyone with the
link could request records the filter was meant to hide, by ID.

## Root cause

`BaseModelSqlv2.readByPk()` built its query only from the primary key, row-level security
and the soft-delete flag. The view's filters weren't part of it. `public-datas.service.ts`
used that call as its "is this record in the shared view?" check
(`packages/nocodb/src/services/public-datas.service.ts`, 2026.07.0):

```ts
// Verify parent row is visible in the shared view before fetching relations
const parentRow = await baseModel.readByPk(param.rowId);
if (!parentRow) {
  NcError.recordNotFound(param.rowId);
}
```

The comment says what the check should do. The call returned the row whether or not the view's
filter matched it. The same pattern appears in three groups of public routes:

| Routes | What they return |
|---|---|
| `GET /api/v{1/db,2}/public/shared-view/:uuid/rows/:rowId/{mm,ln,om}/:columnId` | linked records (many-to-many, links) |
| `GET /api/v{1/db,2}/public/shared-view/:uuid/rows/:rowId/hm/:columnId` | has-many child records |
| `GET /api/v2/public/shared-view/:uuid/downloadAttachment/:columnId/:rowId` | the record's attached files (through the single-record read) |

## Impact

No account is needed: only the share link, which is meant to be passed around, plus the view
password if one is set. Tables created by NocoDB use sequential integer primary keys, so going
through `rowId = 1, 2, 3…` reaches every record the filter excludes. For each one the attacker
can read its linked records and download its attachments.

Typical case: a view shared with a client, filtered to "only this client's rows", over a table
holding every client's data. Anyone with that link could pull the other clients' attachments
and related records.

## Proof of concept

Not published. With a shared view whose filter excludes record 5 (confirm it doesn't appear
in `/rows`), request
`/api/v2/public/shared-view/<uuid>/downloadAttachment/<attachmentColumnId>/5` or
`/rows/5/hm/<columnId>`. Before 2026.08.0 the response contains record 5's data.
After 2026.08.0 it returns "record not found".

## Fix

NocoDB 2026.08.0 adds an `applyViewFilters` option to `readByPk()`. When set, the view's root
filters are added to the query the same way `list()` and `count()` do. All three public routes
above now call it with `applyViewFilters: true`. The same release also strips `getHiddenColumn`
and `nested` from public queries (`sanitizePublicQuery`), so an anonymous caller can't force
hidden columns into the single-record response.

`applyViewFilters` defaults to `false`. Any other place that uses `readByPk()` as a visibility
check for a shared view has to pass it explicitly.

## Timeline

- 2026-06-17 — reported through GitHub private vulnerability reporting
- 2026-08-04 — fixed in NocoDB 2026.08.0
- 2026-11-02 — advisory published
