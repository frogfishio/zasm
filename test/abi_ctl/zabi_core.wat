(module
  (import "env" "zi_abi_version" (func $zi_abi_version (result i32)))
  (import "env" "zi_cap_count" (func $zi_cap_count (result i32)))
  (import "env" "zi_cap_open" (func $zi_cap_open (param i64) (result i32)))
  (import "env" "zi_end" (func $zi_end (param i32) (result i32)))

  (func $lembeh_handle (export "lembeh_handle") (param $req i32) (param $res i32)
    ;; ABI version must be 2.5.
    call $zi_abi_version
    i32.const 0x00020005
    i32.ne
    (if (then unreachable))

    ;; Current zrun harness exposes no caps.
    call $zi_cap_count
    i32.const 0
    i32.ne
    (if (then unreachable))

    ;; Opening any cap must return NOENT (-3) for now.
    i64.const 0
    call $zi_cap_open
    i32.const -3
    i32.ne
    (if (then unreachable))

    local.get $res
    call $zi_end
    drop)
)
