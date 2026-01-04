(module
  (import "lembeh" "req_read"  (func $req_read  (param i32 i32 i32) (result i32)))
  (import "lembeh" "res_write" (func $res_write (param i32 i32 i32) (result i32)))
  (import "lembeh" "res_end"   (func $res_end   (param i32)))

  (import "lembeh" "log"       (func $log       (param i32 i32 i32 i32)))
  (import "lembeh" "alloc"     (func $alloc     (param i32) (result i32)))
  (import "lembeh" "free"      (func $free      (param i32)))

  (memory (export "memory") 1)

  (global $msg i32 (i32.const 8))
  (global $msg_len i32 (i32.const 24))
  (global $__heap_base i32 (i32.const 32))
  (export "__heap_base" (global $__heap_base))

  (data (i32.const 8) "Hello, Zing from Zilog!\0a")

  (func $main (param $req i32) (param $res i32)
    (local $HL i32)
    (local $DE i32)
    (local $A  i32)
    (local $BC i32)
    (local $IX i32)
    (local $HL64 i64)
    (local $DE64 i64)
    (local $A64  i64)
    (local $BC64 i64)
    (local $IX64 i64)
    (local $pc i32)
    (local $cmp i32)
    i32.const 0
    local.set $pc
    (block $exit
      (loop $dispatch
        (block $b0
          (br_table $b0 $exit (local.get $pc))
        )
        ;; line 7: CALL
        local.get $req
        local.get $res
        call $print_hello
        ;; line 8: RET
        br $exit
      )
    )
  )

  (func $print_hello (param $req i32) (param $res i32)
    (local $HL i32)
    (local $DE i32)
    (local $A  i32)
    (local $BC i32)
    (local $IX i32)
    (local $HL64 i64)
    (local $DE64 i64)
    (local $A64  i64)
    (local $BC64 i64)
    (local $IX64 i64)
    (local $pc i32)
    (local $cmp i32)
    i32.const 0
    local.set $pc
    (block $exit
      (loop $dispatch
        (block $b0
          (br_table $b0 $exit (local.get $pc))
        )
        ;; line 11: LD
    global.get $msg
        local.tee $HL
        i64.extend_i32_s
        local.set $HL64
        ;; line 12: LD
    global.get $msg_len
        local.tee $DE
        i64.extend_i32_s
        local.set $DE64
        ;; line 13: CALL
        local.get $res
        local.get $HL
        local.get $DE
        call $res_write
        drop
        ;; line 14: RET
        br $exit
      )
    )
  )

  (func $lembeh_handle (export "lembeh_handle") (param $req i32) (param $res i32)
    local.get $req
    local.get $res
    call $main
    local.get $res
    call $res_end
  )
)
