# zingcore2.5 public headers (WIP)

This directory will contain the **public** headers for the zABI 2.5 runtime.

Rules:

- Headers in this folder define the stable API surface.
- Keep includes minimal and C11-friendly.
- Avoid leaking internal structs; prefer opaque handles.

Status: placeholder (not yet wired into the build).
