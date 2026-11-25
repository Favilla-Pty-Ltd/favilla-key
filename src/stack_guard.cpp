// stack_guard.cpp — stack canaries for the Favilla KEY app (17 Sep 2026).
//
// platformio.ini compiles our code and the vendored libs with
// -fstack-protector-strong. The prebuilt IDF/Arduino libraries were built
// without stack checking, so they do not provide the two symbols the
// instrumented code needs; this file does.
//
// __stack_chk_guard is randomised from the hardware RNG in a constructor,
// which runs before setup() — before any instrumented frame exists on the
// stack, so changing the value there cannot trip a live frame's check.
// A mismatch on function return means a stack buffer was overrun:
// esp_system_abort() panics and the device reboots into (secure-boot-
// verified) firmware rather than executing whatever was written.
#include <stdint.h>
#include <esp_system.h>
#include <esp_random.h>

extern "C" {
  uintptr_t __stack_chk_guard = 0xA5C3F00Du;   // non-zero placeholder until the constructor runs

  __attribute__((constructor))
  static void stack_guard_init(void) {
    __stack_chk_guard = (uintptr_t)esp_random() | 1u;
  }

  void __stack_chk_fail(void) {
    esp_system_abort("stack smashing detected");
  }
}
