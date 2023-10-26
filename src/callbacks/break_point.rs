// SPDX-FileCopyrightText: 2023 Roland Ebrecht <roland.ebrecht@infineon.com>
//
// SPDX-License-Identifier: MIT

use super::Unicorn;

/// Hook for flash_load_img callback handling
///
pub fn hook_code_breakpoint_callback<D>(emu: &mut Unicorn<D>, _address: u64, _size: u32) {
    println!("Breakpoint reached\n");
    emu.emu_stop().unwrap();
}
