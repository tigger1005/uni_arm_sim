// SPDX-FileCopyrightText: 2023 Roland Ebrecht <roland.ebrecht@infineon.com>
//
// SPDX-License-Identifier: MIT

#ifndef H_COMMON
#define H_COMMON

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define UART_OUT_BUF_ADDR ((void *)0x11000000)
// ------------------------------------------------------------

void serial_puts(char *s);
void serial_setup(void);

#endif
