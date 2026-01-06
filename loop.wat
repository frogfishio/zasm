(module
  (import "lembeh" "req_read"  (func $req_read  (param i32 i32 i32) (result i32)))
  (import "lembeh" "res_write" (func $res_write (param i32 i32 i32) (result i32)))
  (import "lembeh" "res_end"   (func $res_end   (param i32)))

  (import "lembeh" "log"       (func $log       (param i32 i32 i32 i32)))
  (import "lembeh" "_ctl"      (func $ctl       (param i32 i32 i32 i32) (result i32)))
  (import "lembeh" "alloc"     (func $alloc     (param i32) (result i32)))
  (import "lembeh" "free"      (func $free      (param i32)))

  (memory (export "memory") 1)

  (global $__heap_base i32 (i32.const 8))
  (export "__heap_base" (global $__heap_base))


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
        (block $b2
        (block $b1
        (block $b0
          (br_table $b0 $b1 $b2 $exit (local.get $pc))
        )
        ;; line 6: LD
    i32.const 0
        local.tee $HL
        i64.extend_i32_s
        local.set $HL64
        ;; line 7: LD
    i32.const 10
        local.tee $DE
        i64.extend_i32_s
        local.set $DE64
        i32.const 1
        local.set $pc
        br $dispatch
        )
        ;; line 10: CP
        local.get $HL
        local.get $DE
        i32.sub
        local.set $cmp
        ;; line 11: JR
        local.get $cmp
        i32.const 0
        i32.ge_s
        (if
          (then
            i32.const 2
            local.set $pc
            br $dispatch
          )
        )
        ;; line 12: INC
        local.get $HL
        i32.const 1
        i32.add
        local.tee $HL
        i64.extend_i32_s
        local.set $HL64
        ;; line 13: JR
        i32.const 1
        local.set $pc
        br $dispatch
        )
        ;; line 15: RET
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
