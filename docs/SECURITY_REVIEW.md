# Security-review identifiers

Comments and documentation across this repository reference finding
identifiers of the form `CRIT-NNN`, `HIGH-NNN`, `MED-NNN` and
`LOW-NNN`.

These reference an **internal security review** conducted before and
during the public release of this codebase. The identifiers follow the
standard severity taxonomy (critical / high / medium / low, numbered
per finding). The review's register — the document mapping each
identifier to its full finding — is internal and not published; the
code comment at each referencing site describes the finding it closes,
which is the part a reader needs.

These identifiers are not from a third-party audit. Where a comment or document says "the audit" or "audit finding" next to one of them, it means this internal review.

ERC-20 token contract audited by SolidProof, zero findings. The protocol, bridge, wallet and embedded code have not been audited yet. The token contract audit is a separate engagement with its own report and does not use these identifiers. The token contract exists on a test network only; no token is live.

The internal review predates the public consolidation of this
repository's git history. Narrative references to the review's own
commit numbering were removed for that reason: those numbers do not
resolve against the published history, and the finding identifiers
alone carry the traceability.
