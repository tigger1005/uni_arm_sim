use super::Unicorn;

mod serial_io;
pub use serial_io::mmio_serial_read_callback;
pub use serial_io::mmio_serial_write_callback;
pub use serial_io::SERIAL_IO_BASE;
