# Zingcore ABI v2 (syscall-style)

This folder defines the **new final micro ABI** for Zing hosts and runtimes.

- Spec: `zingcore/ABI_V2.md`
- C header (native shim API): `zingcore/include/zi_abi_v2.h`
- System ABI header (wire contract): `zingcore/include/zi_sysabi_v2.h`

Design goals:
- Pure `zi_*` C ABI calls (no framed control-plane protocols).
- Works for **native**, **WASM**, and **JIT** embeddings.
- Determinism is explicit (clock/time is a capability, not ambient).
