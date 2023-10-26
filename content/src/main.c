// SPDX-FileCopyrightText: 2023 Roland Ebrecht <roland.ebrecht@infineon.com>
//
// SPDX-License-Identifier: MIT

#include "common.h"

void launch_oem_ram_app(void);

#define GLOBAL_CFI_START_VALUE 0x123B
#define GLOBAL_CFI_END_VALUE (GLOBAL_CFI_START_VALUE - 3)

// Function implementation
__attribute__((used, noinline)) void test_done(void) {}

int main() {
  volatile int run_var = 0;
  serial_setup(); // Set e.g. Baudrate

  serial_puts("Main program\n");
  serial_puts("----------------------\n\n");

  serial_puts("Test 1\n");
  for (int i = 0; i < 1000; i++) {
    run_var++;
  }

  serial_puts("Test 2\n");
  for (int i = 0; i < 1000; i++) {
    run_var++;
  }

  serial_puts("Test 3\n");
  for (int i = 0; i < 1000; i++) {
    run_var++;
  }

  serial_puts("Test 4\n");
  for (int i = 0; i < 1000; i++) {
    run_var++;
  }

  // Signalize with breakpoint end of tests
  test_done();

  return 0;
}
