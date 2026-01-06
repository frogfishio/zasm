#include <stdint.h>
#include <stdio.h>
#include "lembeh_cloak.h"

__attribute__((noinline))
void demo_handle(int32_t req, int32_t res) {
  printf("hello from cloak: req=%d res=%d\n", req, res);
}

int32_t stub_req_read(int32_t req, int32_t ptr, int32_t cap) {
  (void)ptr; (void)cap;
  printf("req_read req=%d\n", req);
  return 0;
}

int32_t stub_res_write(int32_t res, int32_t ptr, int32_t len) {
  (void)ptr; (void)len;
  printf("res_write res=%d\n", res);
  return 0;
}

void stub_res_end(int32_t res) {
  printf("res_end res=%d\n", res);
}

void stub_log(int32_t topic_ptr, int32_t topic_len, int32_t msg_ptr, int32_t msg_len) {
  (void)topic_ptr; (void)topic_len; (void)msg_ptr; (void)msg_len;
  printf("log called\n");
}

int32_t stub_alloc(int32_t size) {
  printf("alloc size=%d\n", size);
  return 16;
}

void stub_free(int32_t ptr) {
  printf("free ptr=%d\n", ptr);
}

int32_t stub_ctl(int32_t req_ptr, int32_t req_len, int32_t resp_ptr, int32_t resp_cap) {
  (void)req_ptr; (void)req_len; (void)resp_ptr; (void)resp_cap;
  printf("ctl called\n");
  return 0;
}

int main(void) {
  uint8_t mem[256];
  lembeh_bind_memory(mem, sizeof(mem));

  lembeh_host_vtable_t host = {
    .req_read = stub_req_read,
    .res_write = stub_res_write,
    .res_end = stub_res_end,
    .log = stub_log,
    .alloc = stub_alloc,
    .free = stub_free,
    .ctl = stub_ctl,
  };
  lembeh_bind_host(&host);

  int rc = lembeh_invoke(demo_handle, 111, 222);
  printf("lembeh_invoke rc=%d\n", rc);
  return rc;
}
