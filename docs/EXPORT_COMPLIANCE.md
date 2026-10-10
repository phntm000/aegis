# Aegis — Export Compliance Notes

This document records the export-control reasoning behind the
`ITSAppUsesNonExemptEncryption` key in `Aegis/Info.plist`. It is not legal
advice. Before the first App Store / TestFlight submission, have counsel
(or the release owner) re-confirm.

## Current setting

`ITSAppUsesNonExemptEncryption = false`

## Basis claimed

Aegis is **free, open-source, publicly available mass-market software**
whose encryption is limited to standard, published cryptographic
algorithms:

- Key agreement: X25519 (RFC 7748) for X3DH and ECDH steps
- Signatures: Ed25519 (RFC 8032)
- Symmetric encryption: AES-256-GCM, ChaCha20-Poly1305 (where used)
- Key derivation: HKDF-SHA256 (RFC 5869)
- Password hashing: Argon2id (RFC 9106)
- Transport: TLS as provided by the OS / relay operator (no custom TLS)

No proprietary or non-standard ciphers, no key escrow, no lawful-intercept
interface, and the source is published at https://github.com/phntm000/aegis.

Under the U.S. Export Administration Regulations (EAR), publicly available
mass-market encryption software of this kind is treated as exempt from the
Encryption Registration Number (ERN) requirement. Setting the plist key to
`false` tells App Store Connect that no ERN is being supplied on this basis.

## Obligations that remain

1. **Annual self-classification report.** Even when exempt from an ERN,
   the BIS expects an annual self-classification report for exported
   encryption items. Calendar this before each year's submission cycle.
2. **Restricted destinations.** Do not distribute to embargoed countries or
   denied parties, per EAR Part 746 and OFAC sanctions — this applies
   regardless of the ERN question.
3. **Re-confirm on scope change.** If Aegis ever adds non-standard crypto,
   a key-escrow/recovery feature, or stops being publicly available source,
   this determination must be redone from scratch.

## Do not flip blindly

If App Store Connect ever challenges the `false` value, do not "fix" it by
flipping to `true` in a drive-by commit — `true` asserts that an ERN has
been obtained and will block submission until one is on file. Resolve the
underlying classification question first, then update this document.
