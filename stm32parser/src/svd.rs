use svd::svd::{Device, Field, Peripheral, Register};
use svd_parser as svd;

pub fn get_peripheral_from_device<'a>(adress: u32, device: &'a Device) -> Peripheral {
    let mut minimum = u64::MAX;
    let mut peripheral_idx = 0;

    for (idx, peripheral) in device.peripherals.iter().enumerate() {
        if peripheral.base_address > adress as u64 {
            continue;
        }

        let diff = adress as u64 - peripheral.base_address;
        if diff >= minimum {
            continue;
        }

        minimum = diff;
        peripheral_idx = idx;
    }

    let mut peripheral = device.peripherals[peripheral_idx].clone();

    if let Some(derived_from) = &peripheral.derived_from {
        peripheral.registers = device
            .get_peripheral(&derived_from)
            .unwrap()
            .registers
            .clone();
    }

    return peripheral;
}

pub fn get_register_from_peripheral<'a>(
    adress: u32,
    peripheral: &'a Peripheral,
) -> Option<&'a Register> {
    let expected_offset = adress as u64 - peripheral.base_address;

    for register in peripheral.registers() {
        if register.address_offset != expected_offset as u32 {
            continue;
        }

        return Some(register);
    }

    None
}

pub fn get_fields_from_register<'a>(
    bit_begin: u32,
    bit_end: u32,
    register: &'a Register,
) -> Vec<&'a Field> {
    let mut fields: Vec<&'a Field> = vec![];

    for field in register.fields() {
        let bit_range = field.bit_range;

        if (bit_range.offset >= bit_begin && bit_range.offset <= bit_end)
            || (bit_range.offset + bit_range.width - 1 >= bit_begin
                && bit_range.offset + bit_range.width - 1 <= bit_end)
        {
            fields.push(field);
        }
    }

    fields
}
