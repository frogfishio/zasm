/*
;; SPDX-FileCopyrightText: 2026 Frogfish
;; SPDX-License-Identifier: Apache-2.0
;; Author: Alexander Croft <alex@frogfish.io>
*/
/* SPDX-License-Identifier: GPL-3.0-or-later */
/*
 * Extracted reactor host capability logic from an older host implementation and
 * the `_ctl` open path.
 *
 * This file captures:
 *   - reactor_frame_t / reactor_host_state_t definitions
 *   - frame validator/state machine (reactor_host_handle)
 *   - frame encoder (reactor_encode_frame)
 *   - host I/O sender/poller helpers (reactor_io_*)
 *   - `_ctl` helper to open the reactor cap (kind="reactor", name="default")
 *
 * Note: This is an extract for ABI work; it is not wired into the runtime.
 */

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/* ---------------- reactor_host.h extract ---------------- */
typedef struct {
  uint32_t kind;    /* 1=event,2=cmd,3=ack,4=log,5=err */
  uint32_t flags;   /* bit0=batch, bit1=compress */
  uint64_t seq;
  uint32_t id_len;
  uint32_t rid_len;
  uint32_t payload_len;
  const uint8_t* id;
  const uint8_t* rid;
  const uint8_t* payload;
} reactor_frame_t;

typedef enum {
  REACTOR_OK = 0,
  REACTOR_ERR_MAGIC,
  REACTOR_ERR_VERSION,
  REACTOR_ERR_LINE,
  REACTOR_ERR_FRAME,
  REACTOR_ERR_ID,
  REACTOR_ERR_RID,
  REACTOR_ERR_RID_STATE,
  REACTOR_ERR_FLAG_BATCH,
  REACTOR_ERR_FLAG_COMPRESS,
  REACTOR_ERR_SEQ_DUP,
  REACTOR_ERR_SEQ_GAP,
  REACTOR_ERR_KIND,
  REACTOR_ERR_OVERFLOW
} reactor_err_t;

typedef enum {
  REACTOR_ACT_NONE = 0,
  REACTOR_ACT_EVENT,
  REACTOR_ACT_CMD,
  REACTOR_ACT_ACK,
  REACTOR_ACT_LOG,
  REACTOR_ACT_ERR
} reactor_action_t;

typedef struct {
  uint64_t expect_seq;    /* last accepted seq */
  uint32_t max_line_bytes;
  int reject_batch;
  int reject_compress;
  uint32_t max_inflight;
  uint32_t inflight;
  int allow_seq_gap;   /* permit non-monotonic seq (accept gaps) */
  int allow_seq_dup;   /* drop duplicates instead of error */
  int backpressure_on; /* set when overflow triggered */
  uint64_t backpressure_hits;
  uint64_t rid_seen;   /* total rid received */
  uint64_t rid_dups;   /* rid duplicates seen */
  uint64_t rid_missing;/* ack/err with no inflight */
#define REACTOR_RID_MAX_SLOTS 8
#define REACTOR_RID_MAX_LEN   64
  uint8_t  rid_slot[REACTOR_RID_MAX_SLOTS][REACTOR_RID_MAX_LEN];
  uint32_t rid_slot_len[REACTOR_RID_MAX_SLOTS];
  uint64_t rid_slot_seq[REACTOR_RID_MAX_SLOTS];
  int      rid_slot_used[REACTOR_RID_MAX_SLOTS];
  uint32_t rid_slot_count;
  uint32_t rid_max_slots; /* <= REACTOR_RID_MAX_SLOTS */
  uint64_t frames_ok;
  uint64_t frames_drop;
  reactor_err_t last_err;
  uint64_t last_seq;
} reactor_host_state_t;

static int flag_on(uint32_t flags, uint32_t mask) { return (flags & mask) != 0; }

void reactor_host_init(reactor_host_state_t* st,
                       uint32_t max_line_bytes,
                       int reject_batch,
                       int reject_compress,
                       uint32_t max_inflight) {
  if (!st) return;
  st->expect_seq = 0;
  st->max_line_bytes = max_line_bytes;
  st->reject_batch = reject_batch;
  st->reject_compress = reject_compress;
  st->max_inflight = max_inflight;
  st->inflight = 0;
  st->allow_seq_gap = 0;
  st->allow_seq_dup = 0;
  st->backpressure_on = 0;
  st->backpressure_hits = 0;
  st->rid_seen = 0;
  st->rid_dups = 0;
  st->rid_missing = 0;
  st->rid_slot_count = 0;
  st->rid_max_slots = REACTOR_RID_MAX_SLOTS;
  for (size_t i = 0; i < REACTOR_RID_MAX_SLOTS; i++) {
    st->rid_slot_len[i] = 0;
    st->rid_slot_seq[i] = 0;
    st->rid_slot_used[i] = 0;
  }
  st->frames_ok = 0;
  st->frames_drop = 0;
  st->last_err = REACTOR_OK;
  st->last_seq = 0;
}

void reactor_host_set_rid_slots(reactor_host_state_t* st, uint32_t slots) {
  if (!st) return;
  if (slots == 0) slots = 1;
  if (slots > REACTOR_RID_MAX_SLOTS) slots = REACTOR_RID_MAX_SLOTS;
  st->rid_max_slots = slots;
}

static reactor_err_t reactor_decode_frame(const uint8_t* buf, size_t len,
                                          reactor_host_state_t* st, reactor_frame_t* out) {
  if (len < 32) return REACTOR_ERR_FRAME;
  if (buf[0] != 'Z' || buf[1] != 'R' || buf[2] != 'X' || buf[3] != '1') return REACTOR_ERR_MAGIC;
  uint16_t v = (uint16_t)(buf[4] | (buf[5] << 8));
  if (v != 1) return REACTOR_ERR_VERSION;
  uint16_t kind = (uint16_t)(buf[6] | (buf[7] << 8));
  uint32_t flags = (uint32_t)(buf[8] | (buf[9] << 8) | (buf[10] << 16) | (buf[11] << 24));
  uint32_t seq_lo = (uint32_t)(buf[12] | (buf[13] << 8) | (buf[14] << 16) | (buf[15] << 24));
  uint32_t seq_hi = (uint32_t)(buf[16] | (buf[17] << 8) | (buf[18] << 16) | (buf[19] << 24));
  uint64_t seq = ((uint64_t)seq_hi << 32) | seq_lo;
  uint32_t id_len = (uint32_t)(buf[20] | (buf[21] << 8) | (buf[22] << 16) | (buf[23] << 24));
  uint32_t rid_len = (uint32_t)(buf[24] | (buf[25] << 8) | (buf[26] << 16) | (buf[27] << 24));
  uint32_t payload_len = (uint32_t)(buf[28] | (buf[29] << 8) | (buf[30] << 16) | (buf[31] << 24));
  uint64_t total = 32ull + id_len + rid_len + payload_len;
  if (total > len) return REACTOR_ERR_FRAME;
  if (st->max_line_bytes && total > st->max_line_bytes) return REACTOR_ERR_LINE;
  if (id_len == 0) return REACTOR_ERR_ID;
  if ((kind == 2 || kind == 3 || kind == 5) && rid_len == 0) return REACTOR_ERR_RID;
  if (flag_on(flags, 1) && st->reject_batch) return REACTOR_ERR_FLAG_BATCH;
  if (flag_on(flags, 2) && st->reject_compress) return REACTOR_ERR_FLAG_COMPRESS;

  size_t id_off = 32;
  size_t rid_off = id_off + id_len;
  size_t payload_off = rid_off + rid_len;
  out->kind = kind;
  out->flags = flags;
  out->seq = seq;
  out->id_len = id_len;
  out->rid_len = rid_len;
  out->payload_len = payload_len;
  out->id = buf + id_off;
  out->rid = buf + rid_off;
  out->payload = buf + payload_off;
  return REACTOR_OK;
}

static reactor_action_t reactor_classify(uint32_t kind) {
  switch (kind) {
    case 1: return REACTOR_ACT_EVENT;
    case 2: return REACTOR_ACT_CMD;
    case 3: return REACTOR_ACT_ACK;
    case 4: return REACTOR_ACT_LOG;
    case 5: return REACTOR_ACT_ERR;
    default: return REACTOR_ACT_NONE;
  }
}

static int rid_len_ok(uint32_t len) { return len > 0 && len <= REACTOR_RID_MAX_LEN; }

static int rid_find(const reactor_host_state_t* st, const uint8_t* rid, uint32_t rid_len, size_t* out_idx) {
  for (size_t i = 0; i < REACTOR_RID_MAX_SLOTS; i++) {
    if (!st->rid_slot_used[i]) continue;
    if (st->rid_slot_len[i] == rid_len &&
        memcmp(st->rid_slot[i], rid, rid_len) == 0) {
      if (out_idx) *out_idx = i;
      return 1;
    }
  }
  return 0;
}

static int rid_add(reactor_host_state_t* st, const reactor_frame_t* f) {
  if (!rid_len_ok(f->rid_len)) return 0;
  if (rid_find(st, f->rid, f->rid_len, NULL)) return 0;
  if (st->rid_slot_count >= st->rid_max_slots) return 0;
  for (size_t i = 0; i < REACTOR_RID_MAX_SLOTS; i++) {
    if (!st->rid_slot_used[i]) {
      memcpy(st->rid_slot[i], f->rid, f->rid_len);
      st->rid_slot_len[i] = f->rid_len;
      st->rid_slot_seq[i] = f->seq;
      st->rid_slot_used[i] = 1;
      st->rid_slot_count += 1;
      return 1;
    }
  }
  return 0;
}

static int rid_remove(reactor_host_state_t* st, const uint8_t* rid, uint32_t rid_len) {
  size_t idx = 0;
  if (!rid_find(st, rid, rid_len, &idx)) return 0;
  st->rid_slot_used[idx] = 0;
  st->rid_slot_len[idx] = 0;
  st->rid_slot_seq[idx] = 0;
  if (st->rid_slot_count > 0) st->rid_slot_count -= 1;
  return 1;
}

reactor_err_t reactor_host_handle(const uint8_t* buf, size_t len,
                                  reactor_host_state_t* st,
                                  reactor_frame_t* out_frame,
                                  reactor_action_t* out_action) {
  if (!buf || !st || !out_frame || !out_action) return REACTOR_ERR_FRAME;
  reactor_frame_t f;
  reactor_err_t err = reactor_decode_frame(buf, len, st, &f);
  if (err != REACTOR_OK) {
    st->frames_drop += 1;
    st->last_err = err;
    return err;
  }

  /* seq policy */
  if (f.seq == st->expect_seq) {
    if (st->allow_seq_dup) {
      st->frames_drop += 1;
      st->last_err = REACTOR_ERR_SEQ_DUP;
      *out_action = REACTOR_ACT_NONE;
      return REACTOR_OK;
    }
    st->frames_drop += 1;
    st->last_err = REACTOR_ERR_SEQ_DUP;
    return REACTOR_ERR_SEQ_DUP;
  }
  if (f.seq != st->expect_seq + 1) {
    if (!st->allow_seq_gap) {
      st->frames_drop += 1;
      st->last_err = REACTOR_ERR_SEQ_GAP;
      return REACTOR_ERR_SEQ_GAP;
    }
  }

  reactor_action_t act = reactor_classify(f.kind);
  if (act == REACTOR_ACT_NONE) {
    st->frames_drop += 1;
    st->last_err = REACTOR_ERR_KIND;
    return REACTOR_ERR_KIND;
  }

  if (act == REACTOR_ACT_CMD) {
    if (!rid_add(st, &f)) {
      st->rid_dups += 1;
      st->frames_drop += 1;
      st->last_err = REACTOR_ERR_RID_STATE;
      return REACTOR_ERR_RID_STATE;
    }
    st->inflight += 1;
    if (st->max_inflight && st->inflight > st->max_inflight) {
      st->inflight -= 1;
      rid_remove(st, f.rid, f.rid_len);
      st->frames_drop += 1;
      st->last_err = REACTOR_ERR_OVERFLOW;
      st->backpressure_on = 1;
      st->backpressure_hits += 1;
      return REACTOR_ERR_OVERFLOW;
    }
  } else if (act == REACTOR_ACT_ACK || act == REACTOR_ACT_ERR) {
    st->rid_seen += 1;
    if (st->inflight == 0) {
      st->rid_missing += 1;
      st->frames_drop += 1;
      st->last_err = REACTOR_ERR_RID_STATE;
      return REACTOR_ERR_RID_STATE;
    }
    if (!rid_len_ok(f.rid_len) || !rid_remove(st, f.rid, f.rid_len)) {
      st->rid_dups += 1;
      st->frames_drop += 1;
      st->last_err = REACTOR_ERR_RID_STATE;
      return REACTOR_ERR_RID_STATE;
    }
    st->inflight -= 1;
  }

  st->expect_seq = f.seq;
  st->last_seq = f.seq;
  st->frames_ok += 1;
  st->last_err = REACTOR_OK;
  if (st->inflight == 0) st->backpressure_on = 0;
  *out_frame = f;
  *out_action = act;
  return REACTOR_OK;
}

size_t reactor_encode_frame(uint8_t* buf, size_t cap,
                            uint32_t kind, uint32_t flags, uint64_t seq,
                            const uint8_t* id, uint32_t id_len,
                            const uint8_t* rid, uint32_t rid_len,
                            const uint8_t* payload, uint32_t payload_len,
                            uint32_t max_line_bytes) {
  uint64_t total = 32ull + id_len + rid_len + payload_len;
  if (max_line_bytes && total > max_line_bytes) return 0;
  if (cap < total) return 0;
  memset(buf, 0, (size_t)total);
  buf[0] = 'Z'; buf[1] = 'R'; buf[2] = 'X'; buf[3] = '1';
  buf[4] = 1; buf[5] = 0;
  buf[6] = (uint8_t)(kind & 0xff);
  buf[7] = (uint8_t)((kind >> 8) & 0xff);
  buf[8] = (uint8_t)(flags & 0xff);
  buf[9] = (uint8_t)((flags >> 8) & 0xff);
  buf[10] = (uint8_t)((flags >> 16) & 0xff);
  buf[11] = (uint8_t)((flags >> 24) & 0xff);
  uint32_t seq_lo = (uint32_t)(seq & 0xffffffffu);
  uint32_t seq_hi = (uint32_t)(seq >> 32);
  buf[12] = (uint8_t)(seq_lo & 0xff);
  buf[13] = (uint8_t)((seq_lo >> 8) & 0xff);
  buf[14] = (uint8_t)((seq_lo >> 16) & 0xff);
  buf[15] = (uint8_t)((seq_lo >> 24) & 0xff);
  buf[16] = (uint8_t)(seq_hi & 0xff);
  buf[17] = (uint8_t)((seq_hi >> 8) & 0xff);
  buf[18] = (uint8_t)((seq_hi >> 16) & 0xff);
  buf[19] = (uint8_t)((seq_hi >> 24) & 0xff);
  buf[20] = (uint8_t)(id_len & 0xff);
  buf[21] = (uint8_t)((id_len >> 8) & 0xff);
  buf[22] = (uint8_t)((id_len >> 16) & 0xff);
  buf[23] = (uint8_t)((id_len >> 24) & 0xff);
  buf[24] = (uint8_t)(rid_len & 0xff);
  buf[25] = (uint8_t)((rid_len >> 8) & 0xff);
  buf[26] = (uint8_t)((rid_len >> 16) & 0xff);
  buf[27] = (uint8_t)((rid_len >> 24) & 0xff);
  buf[28] = (uint8_t)(payload_len & 0xff);
  buf[29] = (uint8_t)((payload_len >> 8) & 0xff);
  buf[30] = (uint8_t)((payload_len >> 16) & 0xff);
  buf[31] = (uint8_t)((payload_len >> 24) & 0xff);
  size_t off = 32;
  if (id_len && id) { memcpy(buf + off, id, id_len); off += id_len; }
  if (rid_len && rid) { memcpy(buf + off, rid, rid_len); off += rid_len; }
  if (payload_len && payload) { memcpy(buf + off, payload, payload_len); off += payload_len; }
  return total;
}

/* ---------------- reactor_io helpers (simplified extract) ---------------- */
typedef struct {
  int32_t (*req_read)(int32_t, int32_t, int32_t);
  int32_t (*res_write)(int32_t, int32_t, int32_t);
  void (*res_end)(int32_t);
} reactor_io_host_vtable_t;

typedef struct {
  const uint8_t* base;
  size_t cap;
} reactor_io_memory_t;

typedef int (*reactor_on_frame_fn)(void* user, const reactor_frame_t* f);
typedef int (*reactor_on_log_fn)(void* user, const reactor_frame_t* f,
                                 const uint8_t* topic, uint32_t topic_len,
                                 const uint8_t* msg, uint32_t msg_len);

typedef struct {
  reactor_on_frame_fn on_cmd;
  reactor_on_frame_fn on_event;
  reactor_on_frame_fn on_ack;
  reactor_on_frame_fn on_err;
  reactor_on_log_fn on_log;
  void* user;
} reactor_handlers_t;

typedef struct {
  int backpressure;       /* 1 if host signalled backpressure */
  reactor_err_t last_err; /* last error from reactor_host_handle */
} reactor_poll_status_t;

typedef struct {
  const reactor_io_host_vtable_t* host;
  const reactor_io_memory_t* mem;
  const reactor_handlers_t* handlers;
  int32_t req_handle;
  int32_t res_handle;
  int32_t rx_off;
  int32_t tx_off;
  uint32_t rx_cap;
  uint32_t tx_cap;
  reactor_host_state_t rx_state; /* tracks guest->host sequencing */
  uint64_t tx_seq;               /* host->guest seq */
  int backpressure;              /* latched backpressure signal */
} reactor_io_ctx_t;

static int reactor_io_send(reactor_io_ctx_t* ctx,
                               uint32_t kind,
                               const uint8_t* id, uint32_t id_len,
                               const uint8_t* rid, uint32_t rid_len,
                               const uint8_t* payload, uint32_t payload_len) {
  uint64_t seq = ctx->tx_seq + 1;
  uint8_t* base = (uint8_t*)ctx->mem->base + ctx->tx_off;
  size_t n = reactor_encode_frame(base, ctx->tx_cap, kind, 0, seq,
                                  id, id_len, rid, rid_len, payload, payload_len,
                                  ctx->rx_state.max_line_bytes);
  if (n == 0) return -1;
  int32_t wrote = ctx->host->res_write(ctx->res_handle, ctx->tx_off, (int32_t)n);
  if (wrote != (int32_t)n) return -1;
  ctx->host->res_end(ctx->res_handle);
  ctx->tx_seq = seq;
  return 0;
}

int reactor_io_send_ack(reactor_io_ctx_t* ctx,
                            const reactor_frame_t* cmd,
                            const uint8_t* payload,
                            uint32_t payload_len) {
  if (!ctx || !cmd) return -1;
  return reactor_io_send(ctx, 3 /* ack */,
                             cmd->id, cmd->id_len,
                             cmd->rid, cmd->rid_len,
                             payload, payload_len);
}

int reactor_io_send_err(reactor_io_ctx_t* ctx,
                            const reactor_frame_t* cmd,
                            const uint8_t* payload,
                            uint32_t payload_len) {
  if (!ctx || !cmd) return -1;
  return reactor_io_send(ctx, 5 /* err */,
                             cmd->id, cmd->id_len,
                             cmd->rid, cmd->rid_len,
                             payload, payload_len);
}

int reactor_io_poll(reactor_io_ctx_t* ctx,
                        reactor_frame_t* out_frame,
                        reactor_action_t* out_action,
                        reactor_err_t* out_err,
                        reactor_poll_status_t* status) {
  if (!ctx || !ctx->host) return -1;
  int32_t got = ctx->host->req_read(ctx->req_handle, ctx->rx_off, (int32_t)ctx->rx_cap);
  if (got <= 0) {
    if (out_err) *out_err = REACTOR_OK;
    if (status) {
      status->backpressure = ctx->backpressure;
      status->last_err = REACTOR_OK;
    }
    return 0;
  }
  const uint8_t* buf = ctx->mem->base + ctx->rx_off;
  reactor_frame_t local_frame;
  reactor_action_t local_action;
  reactor_frame_t* fptr = out_frame ? out_frame : &local_frame;
  reactor_action_t* aptr = out_action ? out_action : &local_action;
  reactor_err_t err = reactor_host_handle(buf, (size_t)got, &ctx->rx_state, fptr, aptr);
  if (out_err) *out_err = err;
  ctx->backpressure = ctx->rx_state.backpressure_on ? 1 : 0;
  if (status) {
    status->backpressure = ctx->backpressure;
    status->last_err = err;
  }
  if (err != REACTOR_OK) return -1;

  if (ctx->handlers) {
    const reactor_frame_t* f = fptr;
    reactor_action_t act = *aptr;
    switch (act) {
      case REACTOR_ACT_CMD:
        if (ctx->handlers->on_cmd) ctx->handlers->on_cmd(ctx->handlers->user, f);
        break;
      case REACTOR_ACT_EVENT:
        if (ctx->handlers->on_event) ctx->handlers->on_event(ctx->handlers->user, f);
        break;
      case REACTOR_ACT_ACK:
        if (ctx->handlers->on_ack) ctx->handlers->on_ack(ctx->handlers->user, f);
        break;
      case REACTOR_ACT_ERR:
        if (ctx->handlers->on_err) ctx->handlers->on_err(ctx->handlers->user, f);
        break;
      case REACTOR_ACT_LOG:
        if (ctx->handlers->on_log) {
          const uint8_t* topic = f->id;
          uint32_t topic_len = f->id_len;
          ctx->handlers->on_log(ctx->handlers->user, f, topic, topic_len, f->payload, f->payload_len);
        }
        break;
      default:
        break;
    }
  }
  return 1;
}

/* ---------------- ctl open helper ---------------- */
static int ctl_write_error(uint8_t* out, size_t cap, uint16_t op, uint32_t rid,
                           const char* trace, const char* msg) {
  uint32_t trace_len = (uint32_t)strlen(trace);
  uint32_t msg_len = (uint32_t)strlen(msg);
  uint32_t payload_len = 4 + 4 + trace_len + 4 + msg_len + 4;
  uint32_t frame_len = 20 + payload_len;
  if (cap < frame_len) return -1;
  memcpy(out + 0, "ZCL1", 4);
  out[4] = 1; out[5] = 0;
  out[6] = (uint8_t)(op & 0xff); out[7] = (uint8_t)((op >> 8) & 0xff);
  out[8] = (uint8_t)(rid & 0xff); out[9] = (uint8_t)((rid >> 8) & 0xff);
  out[10] = (uint8_t)((rid >> 16) & 0xff); out[11] = (uint8_t)((rid >> 24) & 0xff);
  memset(out + 12, 0, 8);
  out[16] = (uint8_t)(payload_len & 0xff);
  out[17] = (uint8_t)((payload_len >> 8) & 0xff);
  out[18] = (uint8_t)((payload_len >> 16) & 0xff);
  out[19] = (uint8_t)((payload_len >> 24) & 0xff);
  out[20] = 0; out[21] = 0; out[22] = 0; out[23] = 0;
  out[24] = (uint8_t)(trace_len & 0xff);
  out[25] = (uint8_t)((trace_len >> 8) & 0xff);
  out[26] = (uint8_t)((trace_len >> 16) & 0xff);
  out[27] = (uint8_t)((trace_len >> 24) & 0xff);
  memcpy(out + 28, trace, trace_len);
  uint32_t off = 28 + trace_len;
  out[off + 0] = (uint8_t)(msg_len & 0xff);
  out[off + 1] = (uint8_t)((msg_len >> 8) & 0xff);
  out[off + 2] = (uint8_t)((msg_len >> 16) & 0xff);
  out[off + 3] = (uint8_t)((msg_len >> 24) & 0xff);
  memcpy(out + off + 4, msg, msg_len);
  memset(out + off + 4 + msg_len, 0, 4);
  return (int)frame_len;
}

static int ctl_write_caps_open_ok(uint8_t* out, size_t cap, uint16_t op, uint32_t rid,
                                  uint32_t handle, uint32_t hflags) {
  const uint32_t payload_len = 4 + 12;
  const uint32_t frame_len = 20 + payload_len;
  if (cap < frame_len) return -1;
  memcpy(out + 0, "ZCL1", 4);
  out[4] = 1; out[5] = 0;
  out[6] = (uint8_t)(op & 0xff); out[7] = (uint8_t)((op >> 8) & 0xff);
  out[8] = (uint8_t)(rid & 0xff); out[9] = (uint8_t)((rid >> 8) & 0xff);
  out[10] = (uint8_t)((rid >> 16) & 0xff); out[11] = (uint8_t)((rid >> 24) & 0xff);
  memset(out + 12, 0, 8);
  out[16] = (uint8_t)(payload_len & 0xff);
  out[17] = (uint8_t)((payload_len >> 8) & 0xff);
  out[18] = (uint8_t)((payload_len >> 16) & 0xff);
  out[19] = (uint8_t)((payload_len >> 24) & 0xff);
  out[20] = 1; out[21] = 0; out[22] = 0; out[23] = 0;
  out[24] = (uint8_t)(handle & 0xff);
  out[25] = (uint8_t)((handle >> 8) & 0xff);
  out[26] = (uint8_t)((handle >> 16) & 0xff);
  out[27] = (uint8_t)((handle >> 24) & 0xff);
  out[28] = (uint8_t)(hflags & 0xff);
  out[29] = (uint8_t)((hflags >> 8) & 0xff);
  out[30] = (uint8_t)((hflags >> 16) & 0xff);
  out[31] = (uint8_t)((hflags >> 24) & 0xff);
  memset(out + 32, 0, 4);
  return (int32_t)frame_len;
}

enum { HANDLE_NONE = 0, HANDLE_REACTOR = 2 };
typedef struct {
  uint8_t* cmd;
  size_t cmd_len;
  size_t cmd_cap;
  uint8_t* read;
  size_t read_len;
  size_t read_cap;
  size_t read_pos;
} reactor_handle_t;

typedef struct {
  reactor_handle_t handles[64];
  uint8_t handle_kind[64];
  int next_handle;
} reactor_env_t;

/*
 * `_ctl` reactor open path (excerpt from cloak_ctl):
 *   kind="reactor", name="default" -> allocate new handle with flags 1|2.
 *   Returns a caps.open OK frame or ctl error.
 */
static int ctl_handle_reactor_open(reactor_env_t* e, uint8_t* out, size_t out_cap,
                                   uint16_t op, uint32_t rid,
                                   uint32_t kind_len, const uint8_t* kind,
                                   uint32_t name_len, const uint8_t* name) {
  if (!(kind_len == 7 && memcmp(kind, "reactor", 7) == 0 &&
        name_len == 7 && memcmp(name, "default", 7) == 0)) {
    return 0; /* not handled */
  }
  if (e->next_handle <= 0 ||
      e->next_handle >= (int)(sizeof(e->handles) / sizeof(e->handles[0]))) {
    return ctl_write_error(out, out_cap, op, rid, "t_ctl_overflow", "handles");
  }
  int handle = e->next_handle++;
  e->handle_kind[handle] = HANDLE_REACTOR;
  uint32_t hflags = 1u | 2u;
  return ctl_write_caps_open_ok(out, out_cap, op, rid, (uint32_t)handle, hflags);
}
