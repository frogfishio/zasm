(module
  (import "lembeh" "_ctl" (func $ctl (param i32 i32 i32 i32) (result i32)))
  (import "lembeh" "res_write" (func $res_write (param i32 i32 i32) (result i32)))
  (memory (export "memory") 1)
  (data (i32.const 0) "ZCL1\01\00\01\00\01\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00")
  (data (i32.const 64) "PATTERN")
  (func (export "lembeh_handle") (param i32 i32)
    (local $n i32)
    (local.set $n
      (call $ctl
        (i32.const 0)
        (i32.const 24)
        (i32.const 64)
        (i32.const 8)))
    (i32.store (i32.const 32) (local.get $n))
    (drop
      (call $res_write
        (i32.const 1)
        (i32.const 32)
        (i32.const 4)))
    (drop
      (call $res_write
        (i32.const 1)
        (i32.const 64)
        (i32.const 7))))
)
