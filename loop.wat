(module
  ;; zABI host surface (syscall-style zi_*)
  (import "env" "zi_abi_version"   (func $zi_abi_version   (result i32)))
  (import "env" "zi_ctl"           (func $zi_ctl           (param i64 i32 i64 i32) (result i32)))
  (import "env" "zi_read"          (func $zi_read          (param i32 i64 i32) (result i32)))
  (import "env" "zi_write"         (func $zi_write         (param i32 i64 i32) (result i32)))
  (import "env" "zi_end"           (func $zi_end           (param i32) (result i32)))
  (import "env" "zi_alloc"         (func $zi_alloc         (param i32) (result i64)))
  (import "env" "zi_free"          (func $zi_free          (param i64) (result i32)))
  (import "env" "zi_telemetry"     (func $zi_telemetry     (param i64 i32 i64 i32) (result i32)))
  (import "env" "zi_cap_count"     (func $zi_cap_count     (result i32)))
  (import "env" "zi_cap_get_size"  (func $zi_cap_get_size  (param i32) (result i32)))
  (import "env" "zi_cap_get"       (func $zi_cap_get       (param i32 i64 i32) (result i32)))
  (import "env" "zi_cap_open"      (func $zi_cap_open      (param i64) (result i32)))
  (import "env" "zi_handle_hflags" (func $zi_handle_hflags (param i32) (result i32)))
  (import "env" "zi_time_now_ms_u32" (func $zi_time_now_ms_u32 (result i32)))
  (import "env" "zi_time_sleep_ms"   (func $zi_time_sleep_ms   (param i32) (result i32)))
  (import "env" "zi_mvar_get_u64"         (func $zi_mvar_get_u64         (param i64) (result i64)))
  (import "env" "zi_mvar_set_default_u64" (func $zi_mvar_set_default_u64 (param i64 i64) (result i64)))
  (import "env" "zi_mvar_get"             (func $zi_mvar_get             (param i64) (result i64)))
  (import "env" "zi_mvar_set_default"     (func $zi_mvar_set_default     (param i64 i64) (result i64)))
  (import "env" "zi_enum_alloc" (func $zi_enum_alloc (param i32 i32 i32) (result i64)))
  (import "env" "zi_exec_run" (func $zi_exec_run (param i64 i32) (result i32)))
  (import "env" "zi_fs_open_path" (func $zi_fs_open_path (param i32 i64 i32) (result i32)))
  (import "env" "zi_hop_alloc" (func $zi_hop_alloc (param i32 i32 i32) (result i64)))
  (import "env" "zi_hop_alloc_buf" (func $zi_hop_alloc_buf (param i32 i32) (result i64)))
  (import "env" "zi_hop_mark" (func $zi_hop_mark (param i32) (result i32)))
  (import "env" "zi_hop_release" (func $zi_hop_release (param i32 i32 i32) (result i32)))
  (import "env" "zi_hop_reset" (func $zi_hop_reset (param i32 i32) (result i32)))
  (import "env" "zi_hop_used" (func $zi_hop_used (param i32) (result i32)))
  (import "env" "zi_hop_cap" (func $zi_hop_cap (param i32) (result i32)))
  (import "env" "zi_read_exact_timeout" (func $zi_read_exact_timeout (param i32 i64 i32 i32) (result i32)))
  (import "env" "zi_zax_read_frame_timeout" (func $zi_zax_read_frame_timeout (param i32 i64 i32 i32) (result i32)))
  (import "env" "zi_zax_q_push" (func $zi_zax_q_push (param i32 i64 i32) (result i32)))
  (import "env" "zi_zax_q_pop" (func $zi_zax_q_pop (param i32 i64 i32) (result i32)))
  (import "env" "zi_zax_q_pop_match" (func $zi_zax_q_pop_match (param i32 i64 i32 i32) (result i32)))
  (import "env" "zi_pump_bytes" (func $zi_pump_bytes (param i32 i32) (result i32)))
  (import "env" "zi_pump_bytes_stage" (func $zi_pump_bytes_stage (param i32 i32 i32) (result i32)))
  (import "env" "zi_pump_bytes_stages" (func $zi_pump_bytes_stages (param i32 i64 i32 i32) (result i32)))
  (import "env" "zi_pump_bytes_stages3" (func $zi_pump_bytes_stages3 (param i32 i64 i32) (result i32)))
  (import "env" "zi_future_scope_new" (func $zi_future_scope_new (param i32 i32 i32) (result i32)))
  (import "env" "zi_future_scope_handle" (func $zi_future_scope_handle (param i32) (result i32)))
  (import "env" "zi_future_scope_lo" (func $zi_future_scope_lo (param i32) (result i32)))
  (import "env" "zi_future_scope_hi" (func $zi_future_scope_hi (param i32) (result i32)))
  (import "env" "zi_future_scope_next_req" (func $zi_future_scope_next_req (param i32) (result i32)))
  (import "env" "zi_future_scope_next_future" (func $zi_future_scope_next_future (param i32) (result i32)))
  (import "env" "zi_future_scope_free" (func $zi_future_scope_free (param i32) (result i32)))
  (import "env" "zi_future_new" (func $zi_future_new (param i32 i32 i32) (result i32)))
  (import "env" "zi_future_scope" (func $zi_future_scope (param i32) (result i32)))
  (import "env" "zi_future_handle" (func $zi_future_handle (param i32) (result i32)))
  (import "env" "zi_future_id_lo" (func $zi_future_id_lo (param i32) (result i32)))
  (import "env" "zi_future_id_hi" (func $zi_future_id_hi (param i32) (result i32)))
  (import "env" "res_end" (func $res_end (param i32) (result i32)))
  (import "env" "res_write_i32" (func $res_write_i32 (param i32 i32) (result i32)))
  (import "env" "res_write_u32" (func $res_write_u32 (param i32 i32) (result i32)))
  (import "env" "res_write_i64" (func $res_write_i64 (param i32 i64) (result i32)))
  (import "env" "res_write_u64" (func $res_write_u64 (param i32 i64) (result i32)))

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
    (local $tmp64 i64)
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

  (export "main" (func $main))
)
