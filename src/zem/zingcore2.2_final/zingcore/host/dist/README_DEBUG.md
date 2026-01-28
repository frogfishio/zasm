# Zingcore Debug Distribution

Contents:
- `lib/`: static libraries (`libzingcore.a`, `libzingcap_*.a`, `libzingmain.a`, `libhopper.a`)
- `include/`: public headers for async/handles/caps and Hopper
- `cap/`: control-plane helper header
- `src/main.c`: test harness used for `demo_app` (depends on `tests/`)
- `src/hopper_sample.c`: minimal standalone Hopper example using `zi_hopper`
- `tests/`: example cap/async/file/exec/net tests

Build the distribution:
```
make -C host dist-debug
```

Link your Zing app (macOS, using force_load to keep plugin objects live):
```
cc build/app.o \
  dist/debug/lib/libhopper.a \
  -Wl,-force_load,dist/debug/lib/libzingcap_async.a \
  -Wl,-force_load,dist/debug/lib/libzingcap_files.a \
  -Wl,-force_load,dist/debug/lib/libzingcap_exec.a \
  -Wl,-force_load,dist/debug/lib/libzingcap_net.a \
  dist/debug/lib/libzingcore.a \
  -o build/app
```

Linux (GNU ld / lld):
```
cc build/app.o \
  dist/debug/lib/libhopper.a \
  -Wl,--whole-archive dist/debug/lib/libzingcap_async.a dist/debug/lib/libzingcap_files.a dist/debug/lib/libzingcap_exec.a dist/debug/lib/libzingcap_net.a -Wl,--no-whole-archive \
  dist/debug/lib/libzingcore.a \
  -o build/app
```

To rebuild the debug harness (uses `src/main.c` + `tests/`):
```
cc -std=c11 -O2 -Wall -Wextra -Idist/debug -Idist/debug/include \
  -c dist/debug/src/main.c dist/debug/tests/*.c
cc -Wl,-force_load,dist/debug/lib/libzingcap_async.a \
   -Wl,-force_load,dist/debug/lib/libzingcap_files.a \
   -Wl,-force_load,dist/debug/lib/libzingcap_exec.a \
   -Wl,-force_load,dist/debug/lib/libzingcap_net.a \
   dist/debug/lib/libzingcore.a dist/debug/lib/libhopper.a dist/debug/tests/*.o dist/debug/src/main.o \
   -o dist/debug/demo_app
```

Build just the Hopper sample:
```
cc -std=c11 -O2 -Wall -Wextra -Idist/debug/include \
  dist/debug/src/hopper_sample.c \
  dist/debug/lib/libhopper.a \
  -o dist/debug/hopper_sample
```

Adjust the link set to include only the capabilities you need.
