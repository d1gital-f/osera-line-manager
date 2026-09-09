# osera-line-manager

The line manager keeps an eye on a supported line and says, from facts it does not own, whether the line is remediated. One record per line, what a bank reads:

```
line, book version, as of, status (remediated or partially remediated),
in scope, fixed (with the promoted coordinates), in progress, open,
not remediable (with the producer's reason), new since the book
```

What it reads: the order book at its tag (what is in scope), the ledger (what the gate promoted or retracted, what a producer declared not remediable), the issues (what a producer took), the advisory sources (what is known that the book does not carry yet). It never reads a producer's own feed and never decides a CVE is fixed on its own authority. The gate decides, the ledger records, the line manager reports.

What it does with the result: opens a pull request on the backlog repository (the book row for a new CVE, the status columns of `supported-lines.csv`) for a person to review, merge and tag. On a tag it writes the signed status file next to the feed and builds the OSERA BOM, one POM pinning every promoted coordinate of the line, uploaded to the intake like any producer's artifact. It never flips a status on its own.

## State of the code

The pure part is done and tested against the real Wave 1 book: `internal/status` computes the record from the book, the ledger and the issues. The command prints it:

```
go run ./cmd/line-manager --book cve-backlog.json --lines supported-lines.csv --ledger ledger.json --book-version v2026.09.09
```

Day one, before the first promotion: `partially remediated, in scope 121, fixed 0, open 121`.

Not built yet, in this order: the ledger read from the gate's store (today a JSON export), the issues read from GitHub, the advisory read, the loop (a ticker and an event hook, every step idempotent, a write ahead intent so it never reacts to its own writes), the pull request, the status file, the BOM.

## Shape

A plain Go service in the shape of a controller: one reconcile function per line, reads then a pure computation then proposals, run on an interval and on events. The contract follows the osramp reconciler (one signal envelope carrying identities not payloads, all I/O in activities, the decision pure), written from scratch under Apache 2.0.

## Layout

| Path | What |
|---|---|
| `cmd/line-manager` | the command |
| `internal/book` | reads `cve-backlog.json` (entry schema 0.5.0) and `supported-lines.csv` |
| `internal/ledger` | reads the ledger export: promoted, retracted, not-remediable events |
| `internal/status` | the computation and its tests |
