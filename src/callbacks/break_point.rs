use super::Unicorn;

/// Hook for flash_load_img callback handling
///
pub fn hook_code_breakpoint_callback<D>(_emu: &mut Unicorn<D>, _address: u64, _size: u32) {
    println!("Breakpoint reached\n");
}