extern crate capstone;

use capstone::prelude::*;
use core::time;
use std::fs::{File, OpenOptions};
use std::io::{Cursor, Read, Seek, SeekFrom};
use std::thread::{sleep, sleep_ms};
use std::vec;
use stm32parser::svd_parser::svd::{Description, Device};
use stm32parser::{
    find_stm_magic_cached, get_peripheral_from_device, get_register_from_peripheral,
    parse_stm_base_header_cached,
};
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

struct MP157State {
    capstone: Capstone,
    device: Device,
    peripherals: MP157PeripheralState,
}

#[allow(non_snake_case)]
#[derive(Default)]
struct MP157PeripheralState {
    RCC_APB1RSTSETR: u32,   // 0x50000980
    RCC_APB1RSTCLRR: u32,   // 0x50000984
    RCC_MP_AHB4ENSETR: u16, // 0x50000A28
    RCC_MP_AHB4ENCLRR: u16, // 0x50000A2C
}

fn main() {
    env_logger::init();

    // Init capstone
    let capstone: Capstone = Capstone::new()
        .arm()
        .mode(arch::arm::ArchMode::Arm)
        .syntax(arch::arm::ArchSyntax::NoRegName)
        .detail(true)
        .build()
        .expect("Failed to create Capstone object");

    // Init SVD device
    let memmap_filename = "../assets/STM32MP157x_v1r6/STM32MP157x.svd";
    let mut memmap_file = File::open(memmap_filename).unwrap();

    let xml = &mut String::new();
    memmap_file.read_to_string(xml).unwrap();

    let device = stm32parser::svd_parser::parse(xml).unwrap();

    // Init emulator
    let emu_data = MP157State {
        capstone,
        device,
        peripherals: MP157PeripheralState::default(),
    };

    let mut unicorn: Unicorn<MP157State> =
        Unicorn::new_with_data(Arch::ARM, Mode::LITTLE_ENDIAN, emu_data)
            .expect("failed to initialize Unicorn instance");
    let emu = &mut unicorn;

    let _ = emu.ctl_set_cpu_model(ArmCpuModel::UC_CPU_ARM_CORTEX_A7 as i32);

    // Secure ROM
    emu.mem_map(0x0000_0000, 128 * 1024, Permission::READ)
        .expect("failed to map ROM page");

    let _ = emu
        .add_mem_hook(
            HookType::MEM_ALL,
            0x0000_0000,
            0x0000_0000 + 128 * 1024,
            hook_memory,
        )
        .expect("failed to add memory hook");

    // Secure SYSRAM
    emu.mem_map(
        0x2FFC_0000,
        256 * 1024,
        Permission::READ | Permission::WRITE,
    )
    .expect("failed to map SYSRAM page");

    let _ = emu
        .add_mem_hook(
            HookType::MEM_ALL,
            0x2FFC_0000,
            0x2FFC_0000 + 256 * 1024,
            hook_memory,
        )
        .expect("failed to add memory hook");

    // Secure DDR
    emu.mem_map(0xC000_0000, 1 * 1024 * 1024 * 1024, Permission::ALL)
        .expect("failed to map DDR page");

    let _ = emu
        .add_mem_hook(
            HookType::MEM_ALL,
            0xC000_0000,
            0xC000_0000 + 1 * 1024 * 1024 * 1024,
            hook_memory,
        )
        .expect("failed to add memory hook");

    // Secure Peripheral memory
    let _ = emu
        .mmio_map(
            0x4000_0000,
            1536 * 1024 * 1024,
            Some(mmio_read_hook),
            Some(mmio_write_hook),
        )
        .expect("failed to add memory hook");

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

    // TODO: Add trustzone support to unicorn
    // Set LSB to unprivledged mode
    // https://developer.arm.com/documentation/107656/0101/Registers/Special-purpose-registers/CONTROL-register
    emu.mem_write(0x2FFE9010, &[0x01, 0x00, 0xA0, 0xE3])
        .unwrap();

    let err = emu.emu_start(address, address + length, 0, 0);
    println!("err={:?}", err);
}

fn hook_memory(
    _: &mut Unicorn<MP157State>,
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

fn mmio_read_hook(emu: &mut Unicorn<MP157State>, offset: u64, _size: usize) -> u64 {
    sleep(time::Duration::from_millis(100));
    let address = 0x4000_0000 + offset;
    log::trace!("Peripheral READ ({:X})", address as u32);

    display_peripheral_info(&emu.get_data().device, address);

    match address {
        0x50000980 => return emu.get_data().peripherals.RCC_APB1RSTSETR as u64,
        0x50000984 => return emu.get_data().peripherals.RCC_APB1RSTCLRR as u64,
        0x50000A28 => return emu.get_data().peripherals.RCC_MP_AHB4ENSETR as u64,
        0x50000A2C => return emu.get_data().peripherals.RCC_MP_AHB4ENCLRR as u64,
        _ => {
            log::warn!("Unsupported peripheral used: {:08X}", address);
            return 0;
        }
    }
}

fn mmio_write_hook(emu: &mut Unicorn<MP157State>, offset: u64, _size: usize, value: u64) -> () {
    let address = 0x4000_0000 + offset;
    log::trace!("Peripheral WRITE ({:X})", address as u32);

    display_peripheral_info(&emu.get_data().device, address);

    let peripheral = &mut emu.get_data_mut().peripherals;

    match address {
        0x50000980 => {
            peripheral.RCC_APB1RSTSETR = value as u32;
            peripheral.RCC_APB1RSTCLRR &= !value as u32;
            return;
        }
        0x50000984 => {
            peripheral.RCC_APB1RSTSETR &= !value as u32;
            peripheral.RCC_APB1RSTCLRR = value as u32;
            return;
        }
        0x50000A28 => {
            peripheral.RCC_MP_AHB4ENSETR = value as u16;
            peripheral.RCC_MP_AHB4ENCLRR &= !value as u16;
        }
        0x50000A2C => {
            peripheral.RCC_MP_AHB4ENSETR &= !value as u16;
            peripheral.RCC_MP_AHB4ENCLRR = value as u16;
        }
        _ => {
            log::warn!("Unsupported peripheral used: {:08X}", address);
            return;
        }
    }
}

fn display_peripheral_info(device: &Device, address: u64) -> () {
    let peripheral = get_peripheral_from_device(address as u32, &device);
    log::trace!(
        "A: {} ( {} ) at {:X}",
        peripheral.name,
        peripheral.description().unwrap_or(&String::new()),
        peripheral.base_address,
    );

    let register = get_register_from_peripheral(address as u32, &peripheral).unwrap();
    log::trace!(
        "B: {} ( {} )",
        register.name,
        register.description().unwrap_or(&String::new()),
    );
}

fn hook_block(emu: &mut Unicorn<MP157State>, address: u64, size: u32) {
    let cs = &emu.get_data().capstone;

    let bytes = emu.mem_read_as_vec(address, size as usize).unwrap();
    let insns = cs.disasm_all(&bytes, 0).expect("Failed to disassemble");

    log::trace!("hook_block:  address={:#010X}, size={:?}", address, size);
    log::trace!("disasembled block: \n{}", insns);
}

fn hook_code(_: &mut Unicorn<MP157State>, address: u64, size: u32) {
    log::trace!("hook_code:   address={:#010X}, size={:?}", address, size);
}
