# TODO

- Add peripherias
- Add automatic loading from SVD
- Add TrustZone support( requires changes in Unicorn and QEMU 5 )
- Parse GPT table and only then load into memory
- Check if every parsed field is valid and then calculate checksum
- Lock unicorn to a commit
- Handle errors
- Better excpet and unwrap behaviour
- Fix same register/peripheral adress bug
- Decided if MMIO should be handled as MEM or MMIO hook
- Add option to crash on unsupported peripheral
- Auto generate code based of SVD
