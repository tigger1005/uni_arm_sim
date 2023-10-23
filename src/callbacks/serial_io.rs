use super::Unicorn;

pub const SERIAL_IO_BASE: u64 = 0x11000000;
const SERIAL_IO_BUFFER: u64 = 0;
const SERIAL_IO_CONFIG: u64 = 4;
const SERIAL_IO_CONTROL: u64 = 8;

/// Callback for serial mem IO write access
///
/// This IO write displays printed messages
pub fn mmio_serial_write_callback<D>(emu: &mut Unicorn<D>, address: u64, size: usize, value: u64) {
    match address {
        SERIAL_IO_BUFFER => buffer_write(emu, value as u8),

        SERIAL_IO_CONFIG => config_write(emu, size, value),

        SERIAL_IO_CONTROL => control_write(emu, size, value),

        _ => println!("Invalid bus write access on address {}", address),
    }
}

/// Callback for serial mem IO read access
///
/// This IO read input messages
pub fn mmio_serial_read_callback<D>(emu: &mut Unicorn<D>, address: u64, size: usize) -> u64 {
    match address {
        SERIAL_IO_BUFFER => buffer_read(emu),

        SERIAL_IO_CONFIG => config_read(emu, size),

        SERIAL_IO_CONTROL => control_read(emu, size),

        _ => {
            println!("Invalid bus write access on address {}", address);
            0
        }
    }
}

/// Write to buffer sfr
///
fn buffer_write<D>(_emu: &Unicorn<D>, value: u8) {
    print!("{}", value as u8 as char);
}

/// Read from buffer sfr
///
fn buffer_read<D>(_emu: &Unicorn<D>) -> u64 {
    0xAA as u64
}

/// Write to config sfr
///
fn config_write<D>(_emu: &Unicorn<D>, size: usize, value: u64) {
    println!(
        "Write to config register size: {} value 0x{:x}\n",
        size, value
    )
}

/// Read from config sfr
///
fn config_read<D>(_emu: &Unicorn<D>, size: usize) -> u64 {
    println!("Read from config register size: {}\n", size);
    0xFF112233 as u64
}

/// Write to control sfr
///
fn control_write<D>(_emu: &Unicorn<D>, size: usize, value: u64) {
    print!(
        "Write to control register size: {} value 0x{:x}\n",
        size, value
    )
}

/// Read from control sfr
///
fn control_read<D>(_emu: &Unicorn<D>, size: usize) -> u64 {
    println!("Read from control register size: {}\n", size);
    0xEE223355 as u64
}
