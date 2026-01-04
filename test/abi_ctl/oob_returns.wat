(module
  (import "lembeh" "req_read" (func $req_read (param i32 i32 i32) (result i32)))
  (import "lembeh" "res_write" (func $res_write (param i32 i32 i32) (result i32)))
  (import "lembeh" "_ctl" (func $ctl (param i32 i32 i32 i32) (result i32)))
  (memory (export "memory") 1)
  (data (i32.const 128) "ZCL1\01\00\01\00\01\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00")
  (func (export "lembeh_handle") (param i32 i32)
    (local $r1 i32)
    (local $r2 i32)
    (local $r3 i32)
    (local.set $r1
      (call $req_read
        (i32.const 0)
        (i32.const 65532)
        (i32.const 8)))
    (local.set $r2
      (call $res_write
        (i32.const 1)
        (i32.const 65532)
        (i32.const 8)))
    (local.set $r3
      (call $ctl
        (i32.const 65532)
        (i32.const 24)
        (i32.const 200)
        (i32.const 64)))
    (i32.store (i32.const 64) (local.get $r1))
    (i32.store (i32.const 68) (local.get $r2))
    (i32.store (i32.const 72) (local.get $r3))
    (drop
      (call $res_write
        (i32.const 1)
        (i32.const 64)
        (i32.const 12))))
)
