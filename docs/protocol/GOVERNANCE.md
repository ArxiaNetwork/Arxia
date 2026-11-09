# Governance

> **Status:** protocol changes are proposed as Arxia Improvement Proposals (AIPs) and discussed as pull requests on this repository. No on-chain governance is implemented: there is no voting on proposals, no governance right attached to a token and no DAO.

## Arxia Improvement Proposals (AIPs)

1. **Draft**: the author copies `docs/aips/TEMPLATE.md` and fills in every section.
2. **Review**: the AIP is submitted as a pull request for public discussion (minimum 14 days).
3. **Implementation**: code changes are merged once the AIP is accepted.
4. **Activation**: breaking changes to the wire format are versioned protocol changes and bump the protocol version (see [SERIALIZATION.md](SERIALIZATION.md)).

## AIP Categories

| Category      | Description                        |
|---------------|------------------------------------|
| Core          | Consensus, block format changes    |
| Transport     | New transport protocols            |
| Parameter     | Limits and protocol constants      |
| Informational | Best practices, guidelines         |
