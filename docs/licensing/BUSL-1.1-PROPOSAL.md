# IoT Hunter — BUSL-1.1 Licensing Proposal

**Status: Draft for review only. Not an operative license.**

This document records a proposed future licensing model. It does not replace the repository's current `LICENSE`, grant additional rights, or change the terms of any release.

## Proposed direction

- Project: IoT Hunter
- Proposed licensor: Harsh Saini (MR CYBER PULSE)
- Proposed licensed release: a future release, tentatively IoT Hunter v4.x
- Proposed license: Business Source License 1.1 (BUSL-1.1)
- Proposed Change License: GNU General Public License v3.0 or later
- Proposed Change Date: the fourth anniversary of the first public distribution of each specific version under BUSL-1.1, unless a later/earlier date is expressly and validly specified for that version.

BUSL-1.1 is source-available, not an OSI-approved Open Source license. The complete, unmodified standard license text and its required parameters must be included with any release that actually adopts it. See https://mariadb.com/bsl11/.

## Proposed Additional Use Grant (for legal review)

Subject to the complete BUSL-1.1 terms, production use would be permitted without a separate commercial license for:

1. An individual using IoT Hunter independently for personal purposes and not on behalf of an organization; and
2. An organization with no more than 25 employees worldwide, for that organization's internal production use.

For this proposed threshold, the parties should clarify in the final legal text how part-time employees, controlled affiliates, parent/subsidiary entities, contractors, and temporary workers are counted. A proposed anti-fragmentation rule is to count employees across entities under common control. This definition requires legal review before adoption.

Production use by an organization above the 25-employee threshold would require a separate commercial license from the licensor. Non-production use remains governed by the standard BUSL-1.1 grant.

This is a policy summary, not final Additional Use Grant wording. It must be checked against BUSL-1.1's requirement that the Additional Use Grant not impose additional restrictions on rights already granted by the standard license.

## Existing release treatment

The repository's current `LICENSE` is GNU GPL v3. This proposal does not retroactively change that license. Existing GPL-licensed releases and copies remain subject to the GPL terms under which they were distributed.

A future BUSL release may only be issued after confirming that the licensor has sufficient rights to relicense every included component, including contributions and code carried forward from earlier releases.

## Required checks before adoption

- Complete a copyright and contributor ownership audit.
- Identify all contributors and obtain any permissions/agreements needed for relicensing.
- Audit copied, vendored, generated, and third-party code for license compatibility.
- Review dependencies and bundled assets separately.
- Have the exact Additional Use Grant and commercial terms reviewed by a qualified software licensing lawyer.
- Decide how the 25-employee threshold is measured and documented.
- Prepare a contributor policy for future submissions.
- Prepare a complete BUSL-1.1 license file using the official, unmodified terms and finalized parameters.
- Update README badges, package metadata, release notes, and distribution artifacts only when the new license is approved and effective.

## Important

Do not label the project "Open Source" while a release is under BUSL-1.1. Use "source-available" or "Community + Commercial licensing" instead.

This proposal is not legal advice and must not be treated as an executed commercial agreement.
