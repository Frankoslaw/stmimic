use aho_corasick::AhoCorasick;
use binrw::{BinRead, BinReaderExt};
use core::fmt;
use postcard::{from_bytes, to_allocvec};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs::File;
use std::io::{Cursor, Read, Seek, SeekFrom, Write};
use std::vec;

#[allow(dead_code, non_snake_case)]
#[derive(Serialize, Deserialize, BinRead, Debug, Clone, Copy)]
#[br(magic = b"STM2")]
pub struct MP157BaseHeader {
    pub signature: [u32; 16],
    pub checksum: u32,
    pub version: u32,
    pub length: u32,
    pub entry_point: u32,
    _reserved1: u32,
    pub load_adress: u32,
    _reserved2: u32,
    pub version_number: u32,
    pub option_flags: u32,
    pub ECDSA_algorithm: u32,
    pub public_key: [u32; 16],
    #[br(pad_before(83))]
    pub binary_type: u8,
}

impl fmt::Display for MP157BaseHeader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "checksum: {:#X} \n\
            version: {:08X} \n\
            version_number: {} \n\
            entry adress: {:#X} \n\
            load adress: {:#X} \n\
            length: {} \n\
            option flags: {:03b} \n\
            binary type: {:#X} \n\
            ECDSA_algorithm: {:#b}",
            self.checksum,
            self.version,
            self.version_number,
            self.entry_point,
            self.load_adress,
            self.length,
            self.option_flags,
            self.binary_type,
            self.ECDSA_algorithm
        )
    }
}

#[derive(Serialize, Deserialize, Debug, Default)]
pub struct Cache {
    stm_magic_pos: HashMap<String, Vec<usize>>,
    stm_base_headers: HashMap<String, Vec<MP157BaseHeader>>,
}

pub fn load_cache(mut cache_file: &File) -> Cache {
    let mut cache_bytes: Vec<u8> = vec![];
    cache_file.rewind().unwrap();
    let _ = cache_file.read_to_end(&mut cache_bytes);

    let postcard_res: Result<Cache, postcard::Error> = from_bytes(&cache_bytes);

    return match postcard_res {
        Ok(local_cache) => local_cache,
        Err(e) => {
            log::error!("Failed to load cache file: {:#?}", e);
            Cache::default()
        }
    };
}

pub fn find_stm_magic(input_bytes: &Vec<u8>) -> Vec<usize> {
    let pattern = b"STM2";
    let ac = AhoCorasick::builder()
        .ascii_case_insensitive(true)
        .build([pattern])
        .unwrap();

    let mut matches = vec![];

    for mat in ac.find_iter(&input_bytes) {
        matches.push(mat.start());
    }

    return matches;
}

pub fn find_stm_magic_cached(
    cache_file: &mut File,
    file_uid: &str,
    mut input_file: &File,
) -> Vec<usize> {
    let mut local_cache = load_cache(cache_file);

    return match local_cache.stm_magic_pos.get(file_uid) {
        Some(stm_magic_pos) => stm_magic_pos.to_owned(),
        None => {
            input_file.rewind().unwrap();
            let mut input_bytes: Vec<u8> = vec![];
            let _ = input_file.read_to_end(&mut input_bytes);

            log::warn!("CACHE MISS( find_stm_magic_cached )");
            let stm_magic_pos = find_stm_magic(&input_bytes);
            local_cache
                .stm_magic_pos
                .insert(file_uid.to_string(), stm_magic_pos.clone());

            let cache_bytes = to_allocvec(&local_cache).unwrap();
            cache_file.rewind().unwrap();
            cache_file.write_all(&cache_bytes).unwrap();
            let _ = cache_file.flush();

            stm_magic_pos
        }
    };
}

pub fn parse_stm_base_header(
    input_bytes: &Vec<u8>,
    header_positions: &Vec<usize>,
) -> Vec<MP157BaseHeader> {
    let mut cursor = Cursor::new(input_bytes.clone());
    let mut headers: Vec<MP157BaseHeader> = vec![];

    for mat in header_positions {
        let _ = cursor.seek(SeekFrom::Start(*mat as u64));

        let header: MP157BaseHeader = cursor.read_le().unwrap();
        headers.push(header);

        log::trace!("Header found at position: {:08X}", mat);
    }

    headers
}

pub fn parse_stm_base_header_cached(
    mut cache_file: &File,
    file_uid: &str,
    mut input_file: &File,
    header_positions: &Vec<usize>,
) -> Vec<MP157BaseHeader> {
    let mut local_cache = load_cache(cache_file);

    return match local_cache.stm_base_headers.get(file_uid) {
        Some(stm_base_headers) => stm_base_headers.to_vec(),
        None => {
            input_file.rewind().unwrap();
            let mut input_bytes: Vec<u8> = vec![];
            let _ = input_file.read_to_end(&mut input_bytes);

            log::warn!("CACHE MISS( parse_stm_base_header_cached )");
            let stm_base_headers = parse_stm_base_header(&input_bytes, header_positions);
            local_cache
                .stm_base_headers
                .insert(file_uid.to_string(), stm_base_headers.clone());

            let cache_bytes = to_allocvec(&local_cache).unwrap();
            cache_file.rewind().unwrap();
            cache_file.write_all(&cache_bytes).unwrap();
            let _ = cache_file.flush();

            stm_base_headers
        }
    };
}
