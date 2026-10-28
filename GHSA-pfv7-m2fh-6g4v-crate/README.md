# GHSA-pfv7-m2fh-6g4v — CrateDB: SSRF through `COPY FROM 'http(s)://…'` for any user with DML

- **Advisory:** [GHSA-pfv7-m2fh-6g4v](https://github.com/crate/crate/security/advisories/GHSA-pfv7-m2fh-6g4v)
- **Severity:** Medium · CWE-918 — no CVE assigned
- **Affected:** CrateDB `< 6.5.0` (the advisory says `<= 6.3.0`, but the 6.4.x line does not
  include the fix either) · **Patched:** `6.5.0`, and only once the new settings are enabled (see *Fix*)
- **Status:** publicly disclosed and fixed. Reported by **Pig-Tail** through coordinated disclosure.

## Summary

`COPY <table> FROM '<uri>'` loads data into a table, and the URI can be `http://` or
`https://`. The CrateDB node fetches it and parses the response into the table. The only
access check on this path limits the `file` scheme to superusers (the CVE-2024-24565 fix).
`http` and `https` had no check, no host allowlist and no block for private or link-local
addresses.

A user with nothing more than `DML` on some table could therefore make the node send GET
requests to internal services, read the responses back with a `SELECT`, and do the same with
the cloud metadata endpoint at `169.254.169.254`.

## Root cause

```java
// FileCollectSource.java:102-105 — the only scheme check on the COPY path
if (uri.getScheme().equals("file") && user.isSuperUser() == false) {
    throw new UnauthorizedException(...);
}

// FileReadingIterator.java — only file / s3 / azure have a factory,
// so http and https fall through to URLFileInput
FileInputFactory f = fileInputFactories.get(uri.getScheme());   // null for "http"
...
return new URLFileInput(uri);

// URLFileInput.java:57-59 — the request
URL url = uri.toURL();
return url.openStream();      // server-side GET, follows redirects, no host check
```

`COPY FROM` only requires `Permission.DML` (`AccessControlImpl.java:370-374`). A user can get
that on a table in their own schema.

## Impact

- **Read-SSRF:** the body of any internal HTTP service the node can reach (admin panels,
  internal APIs) ends up in a table the attacker can query. If the body doesn't parse as
  CSV/JSON, the attacker still learns from errors and timing which hosts and ports answer.
- **Cloud metadata:** on cloud deployments the node can reach the instance metadata service,
  and with it, where that service allows plain GETs, the instance's IAM credentials.
- **The node's own HTTP endpoint:** the comment CrateDB added to `crate.yml` for this fix
  says it also stops users with DML from "gaining access as `crate` user by accessing
  localhost:4200". In other words, the node's own HTTP interface, reached from localhost,
  could be used as a way up to the superuser.
- **Redirects:** `openStream()` follows `http → http` redirects, so a URL on a server the
  attacker controls can bounce the request to an internal target.

## Proof of concept

As a user who is not a superuser but has DML on its own table:

```sql
CREATE TABLE t (x STRING);
COPY t FROM 'http://169.254.169.254/latest/meta-data/iam/security-credentials/'
  WITH (format = 'csv');
SELECT * FROM t;   -- returns what the node fetched
```

For the report, the same request call (`new URI(url).toURL().openStream()`) was run against a
server bound to loopback, standing in for an internal endpoint. Both the direct request and
one going through a 302 redirect returned the server's marker string. No real metadata
service was contacted.

## Fix

CrateDB 6.5.0 adds a dedicated HTTP input for `COPY FROM` (`HTTPFileInputFactory`, commits
[`9b67553d29`](https://github.com/crate/crate/commit/9b67553d29),
[`9038b39f81`](https://github.com/crate/crate/commit/9038b39f81),
[`1c376433ea`](https://github.com/crate/crate/commit/1c376433ea)) with two new settings, both
changeable at runtime:

| Setting | Default in code | Default in the shipped `crate.yml` |
|---|---|---|
| `copy_from.http.blocked_hosts` | `[]` (nothing blocked) | `_local_,_site_,_link_` |
| `copy_from.http.redirects` | `normal` (follows redirects except https→http) | `never` |

Before each request the node resolves the host and rejects it if the name or any of its
addresses is in the list. `_local_`, `_site_` and `_link_` cover loopback, private and
link-local addresses.

**Upgrading is not enough.** The safe values only live in the `crate.yml` that comes with
the tarball. The 6.5.0 release notes say so directly: "Existing installations aren't affected
unless the `crate.yml` configuration file is changed as part of the update". An install that
keeps its old `crate.yml`, or that builds its configuration elsewhere (containers, Helm,
configuration management), runs with the code defaults: nothing blocked and redirects
followed. After upgrading, check it:

```sql
SELECT settings['copy_from']['http'] FROM sys.cluster;
```

and if needed set it in `crate.yml`, or at runtime as a superuser:

```sql
SET GLOBAL PERSISTENT "copy_from.http.blocked_hosts" = '_local_,_site_,_link_';
SET GLOBAL PERSISTENT "copy_from.http.redirects" = 'never';
```

Keep redirects at `never`: the blocklist check runs on the host in the original URL. Network
egress rules for the CrateDB nodes, and IMDSv2 or the equivalent on cloud providers, are
still worth having as a second layer.

## Timeline

- 2026-08-26 — fix merged (dedicated HTTP input, `redirects` and `blocked_hosts` settings)
- 2026-10-13 — CrateDB 6.5.0 released
- 2026-10-28 — advisory published
