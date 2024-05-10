use svd_parser as svd;

use std::fs::File;
use std::io::Read;
use stm32parser::{find_stm_magic_cached, parse_stm_base_header_cached};

fn main() {
    let memmap_filename = "../assets/STM32MP157x_v1r6/STM32MP157x.svd";
    let mut memmap_file = File::open(memmap_filename).unwrap();

    let xml = &mut String::new();
    memmap_file.read_to_string(xml).unwrap();

    println!("{:#?}", svd::parse(xml));
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
