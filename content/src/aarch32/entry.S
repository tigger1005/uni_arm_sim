# SPDX-FileCopyrightText: 2023 Roland Ebrecht <roland.ebrecht@infineon.com>
#
# SPDX-License-Identifier: MIT

.globl _start
# Jump to entrypoint
	bl  main
	b .