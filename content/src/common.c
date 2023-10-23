#include "common.h"

// ------------------------------------------------------------
// Framework variable and functions

void __attribute__((noinline)) serial_putc(char c) {
  *(char *)UART_OUT_BUF_ADDR = c;
}

void __attribute__((noinline)) serial_setup(void) {
  // Write to control register
  *(unsigned int *)(UART_OUT_BUF_ADDR + 4) = 0xFE0012EE;
}

void serial_puts(char *s) {
  while (*s) {
    serial_putc(*s);

    s++;
  }
}
