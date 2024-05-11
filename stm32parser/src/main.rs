use svd_parser as svd;
use svd_parser::svd::Description;

use std::fmt::Write;
use std::fs::File;
use std::io::Read;

use stm32parser::{
    find_stm_magic_cached, get_fields_from_register, get_peripheral_from_device,
    get_register_from_peripheral, parse_stm_base_header_cached,
};

fn main() {
    env_logger::init();

    let memmap_filename = "../assets/STM32MP157x_v1r6/STM32MP157x.svd";
    let mut memmap_file = File::open(memmap_filename).unwrap();

    let xml = &mut String::new();
    memmap_file.read_to_string(xml).unwrap();

    let device = svd::parse(xml).unwrap();

    const ADRESS: u32 = 0x50000980;
    const BIT_BEGIN: u8 = 0;
    const BIT_END: u8 = 8;
    log::info!("Searching for peripheral at adress: {}", ADRESS);

    let peripheral = get_peripheral_from_device(ADRESS, &device);
    let register = get_register_from_peripheral(ADRESS, &peripheral).unwrap();
    let fields = get_fields_from_register(BIT_BEGIN as u32, BIT_END as u32, &register);

    let mut msg = "".to_string();

    write!(
        msg,
        "\n\
        A: {} ( {} )",
        peripheral.name,
        peripheral.description().unwrap_or(&String::new()),
    )
    .unwrap();

    write!(
        msg,
        "\n\
        B: {} ( {} )",
        register.name,
        register.description().unwrap_or(&String::new()),
    )
    .unwrap();

    for field in fields {
        write!(
            msg,
            "\n\
            C: {} ( {} ): {} + {}",
            field.name,
            field.description().unwrap_or(&String::new()),
            field.bit_offset(),
            field.bit_width()
        )
        .unwrap();
    }

    log::info!("{}", msg);
}

// fn main() {
//     env_logger::init();

//     let input_filename = "../assets/zegarson/FlashLayout_sdcard_stm32mp157d-ev1-trusted.raw";
//     let cache_filename = "../assets/stm32parse_cache.bin";

//     let input_file = OpenOptions::new().read(true).open(input_filename).unwrap();
//     let mut cache_file = OpenOptions::new()
//         .create(true)
//         .write(true)
//         .read(true)
//         .open(cache_filename)
//         .unwrap();

//     let stm_magic_pos = find_stm_magic_cached(&mut cache_file, input_filename, &input_file);
//     let mut stm_base_headers =
//         parse_stm_base_header_cached(&mut cache_file, input_filename, &input_file, &stm_magic_pos);

//     stm_base_headers.pop();

//     for stm_base_header in stm_base_headers {
//         log::info!("\n{}", stm_base_header);
//     }
// }
