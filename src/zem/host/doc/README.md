# Capability Pack (Normative)

This folder contains the **normative capability specifications** for ABI v1.0.

Important:
- A host MAY implement **zero capabilities**.
- `_ctl` MUST still support `CAPS_LIST` and return an empty list when no capabilities exist.
- Capability contracts are versioned and stable. Implement only what you support.
- All capability payloads are **Hopper binary layouts** (H1/H2/H4/H8, HSTR, HBYTES). No JSON appears on the ABI boundary.

Capability specs in this pack:
- `CAP_FILES_v1.md`
- `CAP_NET_v1.md`
- `CAP_TIME_v1.md`
- `CAP_CRYPTO_v1.md`
- `CAP_ENTROPY_v1.md`
- `CAP_ACCEL_v1.md`
- `CAP_ACCEL_EXT_v1.md`
- `CAP_PROC_v1.md`
- `CAP_SYS_v1.md`
- `CAP_KV_v1.md`
- `CAP_FS_WATCH_v1.md`
- `CAP_REACTOR_v1.md`
