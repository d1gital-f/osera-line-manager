# osera-line-manager

The line manager keeps an eye on every supported line and says, from facts it does not own, whether the line is fixed. It never decides a CVE is fixed on its own authority: the release repository says what the gate promoted, the evidence file next to each jar says which CVEs that release fixes, the board says where each CVE's issue lives, and the line manager reports.

What a bank reads, one row per line in `supported-lines.csv` and one file per line under `status/`:

```
line_id, ecosystem, anchor, components, scope, source,   <- declared by people
status (not fixed, in progress, fixed), book_version, as_of,
in_scope, fixed, in_progress, open, not_remediable, consume   <- written by the line manager
```

`consume` is the OSERA BOM of the line, `org.finos.osera:osera-bom-<line_id>@<date>`, what a bank imports above its own dependency list. Empty until the first promotion.

## State of the code

Every package is built and tested. The loop runs end to end against a fake GitHub and a fake Nexus in its tests, and in a dry run against real ones. What is not proven yet is the first commit through the GitHub API as the App on a real repository, read back as verified; that is the first thing the deployed pod does.

## The two commands

`status` computes one record per line from local files and prints them. No board, no release repository: what the files say and the word that follows.

```
line-manager status --book cve-backlog.json --lines supported-lines.csv --book-version v2026.09.16
```

`run` is the loop. Every setting is read from the environment first, so the Deployment sets names and no flags; a flag of the same meaning overrides it. Secrets come from the environment only.

| Flag | Environment | Default | What |
|---|---|---|---|
| `--owner` | `GITHUB_OWNER` | `dev-finos-osera-forks` | the organisation that holds the backlog repository |
| `--repo` | `GITHUB_REPO` | `backlog` | the backlog repository |
| `--app-id` | `GITHUB_APP_ID` | | the GitHub App id, required |
| `--installation-id` | `GITHUB_INSTALLATION_ID` | | the App's installation id on the organisation, required |
| `--app-key-file` | `GITHUB_APP_KEY_FILE` | `/secrets/github/app-key.pem` | the App's private key, PEM |
| `--board-number` | `BOARD_NUMBER` | `1` | the organisation project number of the board |
| `--nexus-url` | `NEXUS_URL` | | the Nexus address, required |
| `--nexus-user` | `NEXUS_USER` | `line-manager` | the Nexus account |
| | `NEXUS_PASSWORD` | | its password, environment only |
| `--release-repository` | `NEXUS_RELEASE_REPOSITORY` | `osera-releases-maven-01` | the release repository |
| | `WEBHOOK_SECRET` | | what Nexus signs its deliveries with, environment only |
| `--clone-dir` | `CLONE_DIR` | `/data/backlog` | where the clone lives, on a volume |
| `--cache-dir` | `CACHE_DIR` | `/data/cache` | the scan caches, the evidence cache, the scan stamps, the intent note |
| `--interval` | `INTERVAL` | `10m` | time between passes |
| `--rescan-interval` | `RESCAN_INTERVAL` | `168h` | time between two scans of one line's graph |
| `--dev-advisories` | `SCANNER` (grype, the default: grype over the graph file; or sources: OSV, CISA KEV, FIRST EPSS and NVD one by one, kept for comparison), `GRYPE_BINARY`, `DEV_ADVISORIES` | | the dev only advisory file inside the repository, empty in production |
| | `NVD_API_KEY` | | lifts NVD's public pace, environment only |
| `--listen` | `LISTEN` | `:8080` | the health, status and webhook server |
| `--log-level` | `LOG_LEVEL` | `medium` | how much the log says: `low`, `medium` or `high`, see The log |
| `--dry` | `DRY` | `false` | compute and log, write nothing to GitHub or Nexus |
| `--once` | | | one pass, then exit |
| `--local` | | | a directory with the backlog files, read instead of the clone; no GitHub, no Nexus |

```
GITHUB_APP_ID=4940647 GITHUB_INSTALLATION_ID=161618047 GITHUB_APP_KEY_FILE=app.pem \
NEXUS_URL=https://repo.dev.finos.org NEXUS_PASSWORD=... WEBHOOK_SECRET=... \
line-manager run --dev-advisories advisories/dev.json --dry --once
```

The server answers `GET /healthz`, `GET /status/<line_id>.json` from the clone, and `POST /webhook` for Nexus, every delivery checked against the secret. An accepted event on the release repository starts one more pass.

## The log

Every line is the full timestamp in RFC 3339 UTC, a space, one fact. Three levels, `LOG_LEVEL` or `--log-level`:

- `low`: the pass start and end, the per line summary, every write to GitHub or Nexus (commit, pull request, merge, tag, issue, BOM), every error and discrepancy.
- `medium`, the default: `low` plus one line per step: the graph built or kept, the scan summary, the board, the release repository, `validate` pending, green or red.
- `high`: `medium` plus the detail: every Maven run with its duration, every fallback, every evidence file with its CVEs, every staged file, every comment, the Grype database update, the dev advisory file.

## One pass, ten steps

1. The clone is fetched and fast forwarded to origin's main, or reset to it when it moved on its own. The line file, the rules file and the backlog are read as they are. The intent note is read: a commit the clone now carries is done with, a BOM just uploaded is remembered.
2. For every line whose graph is missing, was built from another anchor, another roots rule or other declared components, or carries unresolved nodes, the line is resolved inside the pod with Maven and written as CycloneDX under `graphs/<line_id>/maven.cdx.json`. The line is built the way a bank builds it: one throwaway project whose dependencies are the roots, with the anchor imported, one Maven run, and the resolved tree is the graph, one version of every library because Maven has mediated. The roots are the line's projects, not everything the anchor manages: the anchor's managed artifacts (the BOMs it imports followed) whose group is one of the declared `components`' groups, the anchor's own group included, plus a declared component the anchor does not manage, at its version. A declared component managed at another version pins its whole group: spring-core 5.3.39 over the 5.3.31 Boot 2.7.18 manages moves every Spring Framework artifact to 5.3.39, as explicit entries before the import so they win. The rule, the components and the pins are recorded in the file (`osera:roots`, `osera:components`, `osera:pins`, `osera:method`). If the build fails, the older method takes over and the file says so: every root probed alone in batches (`MAVEN_BATCH_SIZE` components per Maven run, `MAVEN_WORKERS` runs at a time), breadth first until nothing new appears. A line with no components falls back to every managed artifact, the wide graph.
3. For every line whose graph is new, whose backlog is empty, or whose last scan is older than the rescan interval: the graph's components go to OSV, the CISA KEV list, FIRST EPSS and NVD, through disk caches, the rules file says which findings are applicable, and the result is merged into `cve-backlog.json` (an entry already there keeps its status and takes the new facts, a new one is added open, one the scan no longer finds stays), `cve-excluded.json` carries the rest with a reason, `cve-backlog.md` is the table.
4. The board is read once, one paged query. The release repository is listed once, and the evidence file next to every patched coordinate not yet known is read and cached.
5. One record per line: an entry is fixed while a promoted coordinate on its library and version names its CVE, the highest patch wins; not remediable from the label on its issue; in progress when its issue sits in a patch repository; open otherwise. The counts add up to the entries in scope. Discrepancies are listed for a person. The entries go back into the backlog file with their status.
6. When the promoted set of a line moved, a new BOM is built from every coordinate that fixed an entry, versioned by date, uploaded into the release repository with the line manager's own account, the intent noted first, and written under `bom/<line_id>/pom.xml`. Its coordinate is the line's `consume`.
7. The line rows and `status/<line_id>.json` are written.
8. Everything that changed goes into one commit through the GitHub API as the App, on a branch, as a pull request. When `validate` is green the line manager merges it, fetches, and tags `v<date>` when the backlog changed. When it is red the pull request stays open with a comment.
9. The issue of every entry that became fixed or not remediable this pass is closed with the coordinate and the BOM, or the producer's declaration. An issue whose label was withdrawn is reopened.
10. One log line per line: the word and the counts.

A dry run does steps 1 to 5, 7 and 10, and logs what 6, 8 and 9 would do.

## Shape

A plain Go service in the shape of a controller: one pass over every line, reads then a pure computation then outputs, on a ticker and on the Nexus webhook, every step safe to repeat. The clone is read with go-git and never pushed: writes go through GitHub's git database API as the App, so the commits are signed by GitHub. No Dapr, no database, no Kubernetes Job: the Maven resolve runs inside the pod.

## Layout

| Path | What |
|---|---|
| `cmd/line-manager` | the two commands |
| `internal/book` | `cve-backlog.json` (entry schema 0.6.0, a status per entry) and the fifteen column `supported-lines.csv` |
| `internal/status` | the computation and its tests on the real Wave 1 backlog |
| `internal/releases` | the release repository: the paged search, the evidence file next to a jar, the signed Nexus webhook, the upload |
| `internal/board` | the organisation board, one paged query |
| `internal/rules` | `rules/prioritisation.yaml` as data, the eight conditions the code knows |
| `internal/scan` | OSV, CISA KEV, FIRST EPSS, NVD through disk caches, the dev only advisory file, the rules applied, the two backlog files |
| `internal/graph` | the Maven resolve inside the pod and the CycloneDX file |
| `internal/repo` | the clone with go-git, the App's token, the commit through the API, the pull request, the merge, the tag, the issue comments |
| `internal/intent` | the note written before every write, so the line manager never reacts to its own |
| `internal/bom` | the OSERA BOM of a line, its version, its upload |
| `internal/reconcile` | the pass, the loop, the server |
| `.github/workflows/test.yaml` | gofmt, `go vet`, `go test` on push and pull request |

Apache-2.0, the ControlPlane header on every file.
