extern crate capstone;

use capstone::prelude::*;
use std::fs::OpenOptions;
use std::io::{Cursor, Read, Seek, SeekFrom};
use std::vec;
use stm32parser::{find_stm_magic_cached, parse_stm_base_header_cached};
use unicorn_engine::unicorn_const::{Arch, HookType, MemType, Mode, Permission};
use unicorn_engine::{ArmCpuModel, Unicorn};

// fn main() {
//     env_logger::init();

//     // Inspect disk image, handling errors.
//     if let Err(e) = run() {
//         log::error!("Failed to inspect image: {}", e);
//         std::process::exit(1)
//     }
// }

// fn run() -> io::Result<()> {
//     // First parameter is target disk image (optional, default: fixtures sample)
//     let input_filename = "../assets/zegarson/FlashLayout_sdcard_stm32mp157f-dk2-extensible.raw";

//     // Open disk image.
//     let diskpath = std::path::Path::new(&input_filename);
//     let cfg = gpt::GptConfig::new().writable(false);
//     let disk = cfg.open(diskpath)?;

//     // Print GPT layout.
//     log::info!("Disk (primary) header: {:#?}", disk.primary_header());
//     log::info!("Partition layout: {:#?}", disk.partitions());

//     Ok(())
// }

fn main() {
    env_logger::init();

    // Init emulator
    let mut unicorn = Unicorn::new(Arch::ARM, Mode::LITTLE_ENDIAN)
        .expect("failed to initialize Unicorn instance");
    let emu = &mut unicorn;

    let _ = emu.ctl_set_cpu_model(ArmCpuModel::UC_CPU_ARM_CORTEX_A7 as i32);

    // Secure ROM
    emu.mem_map(0x0000_0000, 128 * 1024, Permission::READ)
        .expect("failed to map ROM page");

    // Secure SYSRAM
    emu.mem_map(
        0x2FFC_0000,
        256 * 1024,
        Permission::READ | Permission::WRITE,
    )
    .expect("failed to map SYSRAM page");

    // Secure DDR
    emu.mem_map(0xC000_0000, 1 * 1024 * 1024 * 1024, Permission::ALL)
        .expect("failed to map DDR page");

    // PARSE STM32 binary
    let input_filename = "../assets/zegarson/FlashLayout_sdcard_stm32mp157d-ev1-trusted.raw";
    let cache_filename = "../assets/stm32parse_cache.bin";

    let mut input_file = OpenOptions::new().read(true).open(input_filename).unwrap();
    let mut cache_file = OpenOptions::new()
        .create(true)
        .write(true)
        .read(true)
        .open(cache_filename)
        .unwrap();

    let mut stm_magic_pos = find_stm_magic_cached(&mut cache_file, input_filename, &input_file);
    let mut stm_base_headers =
        parse_stm_base_header_cached(&mut cache_file, input_filename, &input_file, &stm_magic_pos);

    stm_magic_pos.pop();
    stm_base_headers.pop();

    let mut input_bytes = vec![];
    input_file.rewind().unwrap();
    let _ = input_file.read_to_end(&mut input_bytes);

    let mut cursor = Cursor::new(input_bytes.clone());

    let address = stm_base_headers[0].entry_point as u64;
    let length = stm_base_headers[0].length as u64;
    log::info!("Entry adress: {:#X}", address);
    log::info!("Entry length: {:#X}", length);

    for (pos, base_header) in stm_magic_pos.iter().zip(stm_base_headers.iter()) {
        let _ = cursor.seek(SeekFrom::Start(*pos as u64 + 256));

        let n = base_header.length as usize;
        let mut x = Vec::with_capacity(n);
        let _ = cursor.clone().take(n as u64).read_to_end(&mut x);

        let checksum: u32 = x.iter().map(|x| *x as u32).sum();
        assert_eq!(checksum, base_header.checksum);

        log::info!("\n{}", base_header);

        // Checksum is correct
        emu.mem_write(base_header.load_adress as u64, &x)
            .expect("failed to write uboot");
    }

    // Add hooks and run
    let _ = emu
        .add_block_hook(address, address + length, hook_block)
        .expect("failed to add block hook");

    let _ = emu
        .add_code_hook(address, address + length, hook_code)
        .expect("failed to add code hook");

    let _ = emu
        .add_mem_hook(HookType::MEM_ALL, 0, u64::MAX, hook_memory)
        .expect("failed to add memory hook");

    // TODO: Add trustzone support to unicorn
    // Set LSB to unprivledged mode
    // https://developer.arm.com/documentation/107656/0101/Registers/Special-purpose-registers/CONTROL-register
    emu.mem_write(0x2FFE9010, &[0x01, 0x00, 0xA0, 0xE3])
        .unwrap();

    let err = emu.emu_start(address, address + length, 0, 0);
    println!("err={:?}", err);
}

fn hook_memory(
    _: &mut Unicorn<()>,
    mem_type: MemType,
    address: u64,
    size: usize,
    value: i64,
) -> bool {
    log::trace!(
        "hook_memory: address={:#010X}, size={:?}, mem_type={:?}, value={:#X}",
        address,
        size,
        mem_type,
        value
    );
    true
}

fn hook_block(emu: &mut Unicorn<()>, address: u64, size: u32) {
    // TODO: Figure out how to not regenerate it
    let cs: Capstone = Capstone::new()
        .arm()
        .mode(arch::arm::ArchMode::Arm)
        .syntax(arch::arm::ArchSyntax::NoRegName)
        .detail(true)
        .build()
        .expect("Failed to create Capstone object");

    let bytes = emu.mem_read_as_vec(address, size as usize).unwrap();
    let insns = cs.disasm_all(&bytes, 0).expect("Failed to disassemble");

    log::trace!("hook_block:  address={:#010X}, size={:?}", address, size);
    log::trace!("disasembled block: \n{}", insns);
}

fn hook_code(_: &mut Unicorn<()>, address: u64, size: u32) {
    log::trace!("hook_code:   address={:#010X}, size={:?}", address, size);
}
