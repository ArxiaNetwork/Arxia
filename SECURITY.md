# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability, please report it responsibly:

1. **Do not** open a public issue
2. Email the report to arxia.network@proton.me
3. Include steps to reproduce the vulnerability
4. Allow reasonable time for a fix before public disclosure

## Scope

Security issues in the following areas are in scope:

- Cryptographic code (Ed25519 signatures, Blake3 hashing; ChaCha20-Poly1305 and SLIP39 are stubs that return `Unimplemented`)
- Consensus logic (ORV, conflict resolution, quorum)
- Double-spend detection
- Gossip protocol integrity
- Example contract logic in `contracts/` (no contract runtime or sandbox exists)
- Key management and storage

## Audit status

ERC-20 token contract audited by SolidProof, zero findings. The protocol, bridge, wallet and embedded code have not been audited yet.

The `CRIT-`, `HIGH-`, `MED-` and `LOW-` identifiers in code comments refer to an internal security review, not an external audit. See [docs/SECURITY_REVIEW.md](docs/SECURITY_REVIEW.md).

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.1.x   | Yes      |
