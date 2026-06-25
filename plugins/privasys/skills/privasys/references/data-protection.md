# How your data is protected

When an app stores data on Privasys, the storage is encrypted with a **data key
that belongs to you**, the app owner. The platform never sees that key in the
clear, and you decide which code is allowed to read your data.

## Where the key lives

The data-encryption key (DEK) is generated inside confidential hardware (the
vault is itself a set of SGX enclaves) and held split across a **constellation**
of vaults using Shamir secret sharing (k-of-n). At runtime the app enclave
reconstructs the key over RA-TLS directly from the vaults; the management platform
is only a relay and never holds the key. So a fully compromised platform still
cannot read your data.

## You authorize which code reads your data

The key is bound to a precise **measurement**: the enclave's identity plus the
exact app code (image digest / code hash). When you deploy a new version, or the
enclave itself is upgraded, the measurement changes and the vault **locks the
key** until you, the owner, approve the new measurement:

- `apps_versions_pending` shows the new measurement and per-vault progress.
- `apps_versions_promote` (or guided `apps upgrade`) approves it.
- The platform **cannot** approve for you. Until you do, the data stays locked and
  intact on the encrypted volume.

Because builds are reproducible, you can check the digest you are approving
against the source before you release the key to it.

## Other controls

- **Key rotation** (`apps_rotate_key`): rotate the key without re-encrypting the
  data (the per-volume key is re-wrapped, not the data re-written).
- **Separation of duties** (`apps_cosign`): require a *second* team member to
  co-sign a promote, so no single person can authorize new code over the data.
- **Owner-approved upgrades survive data**: approved upgrades reattach the same
  encrypted volume, so data persists across upgrades you allowed and is denied to
  ones you did not.

## Exporting your key (your data, your key)

You can export your data key at any time (portability, escrow, no lock-in). This
is a deliberate, **dangerous** operation:

- It writes the raw key to a **local file you name**, on the user's own machine.
- The key material must **never** be shown in a chat, returned by a tool, logged,
  or sent to any service or model. An assistant must only trigger the export to a
  local file, confirm with the human first, and never read the key back.

More: [docs.privasys.org/solutions/enclave-vaults/overview](https://docs.privasys.org/solutions/enclave-vaults/overview).
