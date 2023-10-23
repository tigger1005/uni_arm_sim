
// Get elf file parser
mod elf_file;
use elf_file::ElfFile;

// Get callbacks
mod callbacks;
use callbacks::*;

// Get unicorn engine
use unicorn_engine::unicorn_const::{Arch, Mode, Permission, SECOND_SCALE};
use unicorn_engine::{RegisterARM, Unicorn};


// Define const variables
const STACK_BASE: u64 = 0x80100000;
const STACK_SIZE: usize = 0x10000;
const CODE_BASE: u64 = 0x1000000;
const BOOT_STAGE: u64 = 0x32000000;
const AUTH_BASE: u64 = 0xAA01000;

const ARM_REG: [RegisterARM; 16] = [
    RegisterARM::R0,
    RegisterARM::R1,
    RegisterARM::R2,
    RegisterARM::R3,
    RegisterARM::R4,
    RegisterARM::R5,
    RegisterARM::R6,
    RegisterARM::R7,
    RegisterARM::R8,
    RegisterARM::R9,
    RegisterARM::R10,
    RegisterARM::R11,
    RegisterARM::R12,
    RegisterARM::SP,
    RegisterARM::LR,
    RegisterARM::PC,
];

fn main() {
    println!("Unicorn ARM simulation");

    // Open and load elf file
    let file_data = ElfFile::new(std::path::PathBuf::from("bin/bl1.elf"));

    // Setup target
    let mut emu = Unicorn::new(Arch::ARM, Mode::LITTLE_ENDIAN | Mode::MCLASS)
        .expect("failed to initialize Unicorn instance");

    // Setup memory mapping, stack, io mapping
    const MINIMUM_MEMORY_SIZE: usize = 0x1000;

    // Next boot stage mem
    emu.mem_map(
        BOOT_STAGE,
        MINIMUM_MEMORY_SIZE,
        Permission::READ | Permission::WRITE,
    )
    .expect("failed to map boot stage page");

    // Code
    let code_size = (file_data.program.len() + MINIMUM_MEMORY_SIZE) & 0xfffff000;
    emu.mem_map(file_data.program_header.p_paddr, code_size, Permission::ALL)
        .expect("failed to map code page");

    // Stack
    emu.mem_map(STACK_BASE, STACK_SIZE, Permission::READ | Permission::WRITE)
        .expect("failed to map stack page");

    // Auth success / failed trigger
    emu.mem_map(AUTH_BASE, MINIMUM_MEMORY_SIZE, Permission::WRITE)
        .expect("failed to map mmio replacement");

    // Serial IO peripheral space
    emu.mmio_map(
        0x11000000,
        MINIMUM_MEMORY_SIZE,
        Some(mmio_serial_read_callback),
        Some(mmio_serial_write_callback),
    )
    .expect("failed to map serial IO");

    // Load source code from elf file into simulation
    emu.mem_write(CODE_BASE, &file_data.program)
        .expect("failed to write file data");

    // Clear registers
    ARM_REG
        .iter()
        .for_each(|reg| emu.reg_write(*reg, 0x00).unwrap());

    // Run simulation
    _ = emu.emu_start(
        file_data.program_header.p_paddr | 1,
        file_data.program_header.p_paddr + file_data.program_header.p_filesz | 1,
        SECOND_SCALE,
        0,
    );
}
