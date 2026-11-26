//! The driver against a register-level model of the SX1276.
//!
//! The model answers SPI transactions the way the chip does in LoRa
//! mode: register reads and writes, the FIFO with its address pointer,
//! the operating modes, the interrupt flags, and a shared "air" that
//! carries a packet from a transmitting chip to the listening ones
//! whose modem settings match. It also records what a real chip would
//! not tolerate, such as changing the LoRa mode bit outside sleep.
//!
//! The model is written from the same reading of the datasheet as the
//! driver. It checks the driver's logic and sequences; it is not
//! evidence about hardware.

use std::cell::RefCell;
use std::convert::Infallible;
use std::rc::Rc;

use arxia_radio::{Bandwidth, RadioConfig, RadioError, Sx127x, CHIP_VERSION, MAX_PAYLOAD_LEN};
use embedded_hal::delay::DelayNs;
use embedded_hal::digital::{ErrorType as PinErrorType, OutputPin};
use embedded_hal::spi::{ErrorType as SpiErrorType, Operation, SpiDevice};

const OP_MODE: usize = 0x01;
const FIFO_ADDR_PTR: usize = 0x0d;
const FIFO_TX_BASE: usize = 0x0e;
const FIFO_RX_BASE: usize = 0x0f;
const FIFO_RX_CURRENT: usize = 0x10;
const IRQ_FLAGS: usize = 0x12;
const RX_NB_BYTES: usize = 0x13;
const PKT_SNR: usize = 0x19;
const PKT_RSSI: usize = 0x1a;
const PAYLOAD_LENGTH: usize = 0x22;
const VERSION: usize = 0x42;

const IRQ_RX_DONE: u8 = 0x40;
const IRQ_CRC_ERROR: u8 = 0x20;
const IRQ_TX_DONE: u8 = 0x08;

/// A packet on the air, with the modem settings it was sent with.
#[derive(Clone)]
struct OnAir {
    sender: usize,
    modem: [u8; 7],
    payload: Vec<u8>,
    corrupt: bool,
}

#[derive(Default)]
struct Air {
    packets: Vec<OnAir>,
}

struct Chip {
    id: usize,
    regs: [u8; 0x80],
    fifo: [u8; 256],
    air: Rc<RefCell<Air>>,
    /// Sequences a real chip would not accept.
    violations: Vec<&'static str>,
    transactions: usize,
    resets: usize,
    /// When set, the chip never reports a transmission complete.
    stuck_tx: bool,
    reset_low: bool,
}

impl Chip {
    fn new(id: usize, air: &Rc<RefCell<Air>>) -> Rc<RefCell<Self>> {
        let mut chip = Self {
            id,
            regs: [0; 0x80],
            fifo: [0; 256],
            air: air.clone(),
            violations: Vec::new(),
            transactions: 0,
            resets: 0,
            stuck_tx: false,
            reset_low: false,
        };
        chip.power_on();
        Rc::new(RefCell::new(chip))
    }

    fn power_on(&mut self) {
        self.regs = [0; 0x80];
        // FSK mode, standby: the state after reset.
        self.regs[OP_MODE] = 0x09;
        self.regs[VERSION] = CHIP_VERSION;
        self.regs[FIFO_TX_BASE] = 0x80;
    }

    fn mode(&self) -> u8 {
        self.regs[OP_MODE] & 0x07
    }

    /// Frequency, bandwidth and coding rate, spreading factor, sync
    /// word: what two chips must share to hear each other.
    fn modem(&self) -> [u8; 7] {
        [
            self.regs[0x06],
            self.regs[0x07],
            self.regs[0x08],
            self.regs[0x1d] & 0xfe,
            self.regs[0x1e] & 0xf0,
            self.regs[0x39],
            0,
        ]
    }

    fn write_reg(&mut self, address: usize, value: u8) {
        match address {
            0x00 => {
                if !matches!(self.mode(), 0 | 1) {
                    self.violations
                        .push("FIFO written outside sleep or standby");
                }
                let pointer = self.regs[FIFO_ADDR_PTR];
                self.fifo[usize::from(pointer)] = value;
                self.regs[FIFO_ADDR_PTR] = pointer.wrapping_add(1);
            }
            OP_MODE => {
                let lora_bit_changes = (value ^ self.regs[OP_MODE]) & 0x80 != 0;
                if lora_bit_changes && self.mode() != 0 {
                    self.violations.push("LoRa mode bit changed outside sleep");
                    return;
                }
                self.regs[OP_MODE] = value;
                if value & 0x80 == 0 {
                    return;
                }
                match value & 0x07 {
                    0 => self.fifo = [0; 256],
                    3 => self.transmit(),
                    _ => {}
                }
            }
            IRQ_FLAGS => self.regs[IRQ_FLAGS] &= !value,
            VERSION => {}
            other => self.regs[other] = value,
        }
    }

    fn read_reg(&mut self, address: usize) -> u8 {
        if address == 0x00 {
            let pointer = self.regs[FIFO_ADDR_PTR];
            self.regs[FIFO_ADDR_PTR] = pointer.wrapping_add(1);
            return self.fifo[usize::from(pointer)];
        }
        self.regs[address]
    }

    fn transmit(&mut self) {
        let start = usize::from(self.regs[FIFO_TX_BASE]);
        let length = usize::from(self.regs[PAYLOAD_LENGTH]);
        let payload = (0..length)
            .map(|offset| self.fifo[(start + offset) % 256])
            .collect();
        self.air.borrow_mut().packets.push(OnAir {
            sender: self.id,
            modem: self.modem(),
            payload,
            corrupt: false,
        });
        if !self.stuck_tx {
            self.regs[IRQ_FLAGS] |= IRQ_TX_DONE;
            // The chip returns to standby by itself after a packet.
            self.regs[OP_MODE] = (self.regs[OP_MODE] & 0xf8) | 0x01;
        }
    }

    /// Hear what is on the air, if listening with matching settings.
    fn hear(&mut self, packet: &OnAir) {
        let listening = self.regs[OP_MODE] & 0x80 != 0 && self.mode() == 5;
        if !listening || packet.sender == self.id || packet.modem != self.modem() {
            return;
        }
        let start = self.regs[FIFO_RX_BASE];
        for (offset, byte) in packet.payload.iter().enumerate() {
            self.fifo[(usize::from(start) + offset) % 256] = *byte;
        }
        self.regs[FIFO_RX_CURRENT] = start;
        self.regs[RX_NB_BYTES] = packet.payload.len() as u8;
        self.regs[PKT_RSSI] = 97; // -60 dBm on the high-frequency port
        self.regs[PKT_SNR] = 36; // 9 dB
        self.regs[IRQ_FLAGS] |= IRQ_RX_DONE;
        if packet.corrupt {
            self.regs[IRQ_FLAGS] |= IRQ_CRC_ERROR;
        }
    }
}

/// The SPI side of a chip.
struct Bus(Rc<RefCell<Chip>>);

impl SpiErrorType for Bus {
    type Error = Infallible;
}

impl SpiDevice for Bus {
    fn transaction(&mut self, operations: &mut [Operation<'_, u8>]) -> Result<(), Infallible> {
        let mut chip = self.0.borrow_mut();
        chip.transactions += 1;
        // The first byte written is the address; bit 7 means write.
        let mut address: Option<(usize, bool)> = None;
        for operation in operations {
            match operation {
                Operation::Write(bytes) => {
                    for byte in bytes.iter() {
                        match address {
                            None => address = Some((usize::from(byte & 0x7f), byte & 0x80 != 0)),
                            Some((at, true)) => {
                                chip.write_reg(at, *byte);
                                if at != 0 {
                                    address = Some((at + 1, true));
                                }
                            }
                            Some((_, false)) => {}
                        }
                    }
                }
                Operation::Read(bytes) => {
                    for byte in bytes.iter_mut() {
                        let (at, _) = address.expect("a read follows an address");
                        *byte = chip.read_reg(at);
                        if at != 0 {
                            address = Some((at + 1, false));
                        }
                    }
                }
                _ => panic!("the driver uses only Write and Read"),
            }
        }
        Ok(())
    }
}

/// The reset pin of a chip: a low-then-high pulse resets it.
struct ResetPin(Rc<RefCell<Chip>>);

impl PinErrorType for ResetPin {
    type Error = Infallible;
}

impl OutputPin for ResetPin {
    fn set_low(&mut self) -> Result<(), Infallible> {
        self.0.borrow_mut().reset_low = true;
        Ok(())
    }
    fn set_high(&mut self) -> Result<(), Infallible> {
        let mut chip = self.0.borrow_mut();
        if chip.reset_low {
            chip.reset_low = false;
            chip.resets += 1;
            chip.power_on();
        }
        Ok(())
    }
}

struct NoDelay;

impl DelayNs for NoDelay {
    fn delay_ns(&mut self, _ns: u32) {}
}

type Radio = Sx127x<Bus, ResetPin, NoDelay>;

struct Station {
    chip: Rc<RefCell<Chip>>,
    radio: Radio,
}

fn station(id: usize, air: &Rc<RefCell<Air>>, config: RadioConfig) -> Station {
    let chip = Chip::new(id, air);
    let radio = Sx127x::new(Bus(chip.clone()), ResetPin(chip.clone()), NoDelay, config)
        .expect("the radio initialises");
    Station { chip, radio }
}

/// Let every station hear what was transmitted, then clear the air.
fn propagate(air: &Rc<RefCell<Air>>, stations: &[&Station]) {
    let packets = std::mem::take(&mut air.borrow_mut().packets);
    for packet in &packets {
        for station in stations {
            station.chip.borrow_mut().hear(packet);
        }
    }
}

fn config() -> RadioConfig {
    RadioConfig::at(915_000_000)
}

#[test]
fn initialisation_resets_the_chip_and_leaves_it_in_lora_standby() {
    let air = Rc::new(RefCell::new(Air::default()));
    let a = station(1, &air, config());
    let chip = a.chip.borrow();
    assert_eq!(chip.resets, 1);
    assert_eq!(chip.regs[OP_MODE], 0x81, "LoRa mode, standby");
    assert!(chip.violations.is_empty(), "{:?}", chip.violations);
}

#[test]
fn the_frequency_registers_follow_the_datasheet_formula() {
    let air = Rc::new(RefCell::new(Air::default()));
    // Frf = frequency * 2^19 / 32 MHz.
    let a = station(1, &air, RadioConfig::at(915_000_000));
    assert_eq!(a.chip.borrow().regs[0x06..0x09], [0xe4, 0xc0, 0x00]);
    let b = station(2, &air, RadioConfig::at(868_000_000));
    assert_eq!(b.chip.borrow().regs[0x06..0x09], [0xd9, 0x00, 0x00]);
}

#[test]
fn the_modem_registers_carry_the_configuration() {
    let air = Rc::new(RefCell::new(Air::default()));
    let a = station(1, &air, config());
    let chip = a.chip.borrow();
    // 125 kHz, coding rate 4/5, explicit header.
    assert_eq!(chip.regs[0x1d], 0x72);
    // Spreading factor 9, payload CRC on.
    assert_eq!(chip.regs[0x1e], 0x94);
    // Automatic gain control, no low data rate optimisation.
    assert_eq!(chip.regs[0x26], 0x04);
    // PA_BOOST, 14 dBm.
    assert_eq!(chip.regs[0x09], 0x8c);
    assert_eq!(chip.regs[0x39], 0x2b);
    assert_eq!(chip.regs[0x20..0x22], [0x00, 0x08]);
}

#[test]
fn long_symbols_switch_on_low_data_rate_optimisation() {
    let air = Rc::new(RefCell::new(Air::default()));
    let slow = RadioConfig {
        spreading_factor: 12,
        ..config()
    };
    assert_eq!(slow.symbol_micros(), 32_768);
    let a = station(1, &air, slow);
    assert_eq!(a.chip.borrow().regs[0x26], 0x0c);
}

#[test]
fn a_packet_crosses_from_one_radio_to_another() {
    let air = Rc::new(RefCell::new(Air::default()));
    let mut a = station(1, &air, config());
    let mut b = station(2, &air, config());
    b.radio.start_receive().unwrap();

    a.radio
        .transmit(b"value moves without internet", 1_000)
        .unwrap();
    propagate(&air, &[&a, &b]);

    let mut buffer = [0u8; MAX_PAYLOAD_LEN];
    let received = b
        .radio
        .poll_receive(&mut buffer)
        .unwrap()
        .expect("a packet");
    assert_eq!(&buffer[..received.len], b"value moves without internet");
    assert_eq!(received.rssi_dbm, -60);
    assert_eq!(received.snr_quarter_db, 36);
    // Collected once.
    assert_eq!(b.radio.poll_receive(&mut buffer).unwrap(), None);
    assert!(a.chip.borrow().violations.is_empty());
    assert!(b.chip.borrow().violations.is_empty());
}

#[test]
fn the_largest_packet_round_trips_and_a_larger_one_is_refused() {
    let air = Rc::new(RefCell::new(Air::default()));
    let mut a = station(1, &air, config());
    let mut b = station(2, &air, config());
    b.radio.start_receive().unwrap();

    let largest: Vec<u8> = (0..MAX_PAYLOAD_LEN).map(|i| (i * 7 % 251) as u8).collect();
    a.radio.transmit(&largest, 1_000).unwrap();
    propagate(&air, &[&a, &b]);
    let mut buffer = [0u8; MAX_PAYLOAD_LEN];
    let received = b.radio.poll_receive(&mut buffer).unwrap().unwrap();
    assert_eq!(received.len, MAX_PAYLOAD_LEN);
    assert_eq!(&buffer[..], &largest[..]);

    let too_long = vec![0u8; MAX_PAYLOAD_LEN + 1];
    assert_eq!(
        a.radio.transmit(&too_long, 1_000),
        Err(RadioError::PayloadLength(256))
    );
    assert_eq!(
        a.radio.transmit(&[], 1_000),
        Err(RadioError::PayloadLength(0))
    );
    assert!(air.borrow().packets.is_empty(), "nothing was transmitted");
}

#[test]
fn radios_with_different_settings_do_not_hear_each_other() {
    let air = Rc::new(RefCell::new(Air::default()));
    let mut a = station(1, &air, config());
    let mut other_frequency = station(2, &air, RadioConfig::at(868_000_000));
    let mut other_spreading = station(
        3,
        &air,
        RadioConfig {
            spreading_factor: 7,
            ..config()
        },
    );
    let mut other_sync = station(
        4,
        &air,
        RadioConfig {
            sync_word: 0x34,
            ..config()
        },
    );
    let mut other_bandwidth = station(
        5,
        &air,
        RadioConfig {
            bandwidth: Bandwidth::Khz250,
            ..config()
        },
    );
    let mut listeners = [
        &mut other_frequency,
        &mut other_spreading,
        &mut other_sync,
        &mut other_bandwidth,
    ];
    for listener in listeners.iter_mut() {
        listener.radio.start_receive().unwrap();
    }
    a.radio.transmit(b"hello", 1_000).unwrap();
    let packets = std::mem::take(&mut air.borrow_mut().packets);
    let mut buffer = [0u8; MAX_PAYLOAD_LEN];
    for listener in listeners.iter_mut() {
        listener.chip.borrow_mut().hear(&packets[0]);
        assert_eq!(listener.radio.poll_receive(&mut buffer).unwrap(), None);
    }
}

#[test]
fn a_packet_with_a_bad_checksum_is_dropped_and_the_next_one_is_received() {
    let air = Rc::new(RefCell::new(Air::default()));
    let mut a = station(1, &air, config());
    let mut b = station(2, &air, config());
    b.radio.start_receive().unwrap();

    a.radio.transmit(b"damaged on the way", 1_000).unwrap();
    air.borrow_mut().packets[0].corrupt = true;
    propagate(&air, &[&a, &b]);
    let mut buffer = [0u8; MAX_PAYLOAD_LEN];
    assert_eq!(b.radio.poll_receive(&mut buffer).unwrap(), None);

    a.radio.transmit(b"intact", 1_000).unwrap();
    propagate(&air, &[&a, &b]);
    let received = b.radio.poll_receive(&mut buffer).unwrap().unwrap();
    assert_eq!(&buffer[..received.len], b"intact");
}

#[test]
fn a_radio_that_is_not_listening_misses_the_packet() {
    let air = Rc::new(RefCell::new(Air::default()));
    let mut a = station(1, &air, config());
    let mut b = station(2, &air, config());
    a.radio.transmit(b"nobody home", 1_000).unwrap();
    propagate(&air, &[&a, &b]);
    b.radio.start_receive().unwrap();
    let mut buffer = [0u8; MAX_PAYLOAD_LEN];
    assert_eq!(b.radio.poll_receive(&mut buffer).unwrap(), None);
}

#[test]
fn a_transmission_that_never_completes_times_out_and_returns_to_standby() {
    let air = Rc::new(RefCell::new(Air::default()));
    let mut a = station(1, &air, config());
    a.chip.borrow_mut().stuck_tx = true;
    assert_eq!(a.radio.transmit(b"stuck", 50), Err(RadioError::TxTimeout));
    assert_eq!(a.chip.borrow().regs[OP_MODE], 0x81);
}

#[test]
fn a_chip_that_does_not_answer_as_an_sx1276_is_refused() {
    struct Absent;
    impl SpiErrorType for Absent {
        type Error = Infallible;
    }
    impl SpiDevice for Absent {
        fn transaction(&mut self, operations: &mut [Operation<'_, u8>]) -> Result<(), Infallible> {
            // A floating bus reads zeros.
            for operation in operations {
                if let Operation::Read(bytes) = operation {
                    bytes.fill(0);
                }
            }
            Ok(())
        }
    }
    let air = Rc::new(RefCell::new(Air::default()));
    let chip = Chip::new(1, &air);
    let outcome = Sx127x::new(Absent, ResetPin(chip), NoDelay, config());
    assert!(matches!(outcome, Err(RadioError::VersionMismatch(0))));
}

#[test]
fn settings_out_of_range_are_refused_before_the_bus_is_touched() {
    let air = Rc::new(RefCell::new(Air::default()));
    let invalid = [
        RadioConfig::at(433_000_000),
        RadioConfig {
            spreading_factor: 6,
            ..config()
        },
        RadioConfig {
            spreading_factor: 13,
            ..config()
        },
        RadioConfig {
            coding_rate: 4,
            ..config()
        },
        RadioConfig {
            tx_power_dbm: 20,
            ..config()
        },
        RadioConfig {
            tx_power_dbm: 1,
            ..config()
        },
        RadioConfig {
            preamble_symbols: 5,
            ..config()
        },
    ];
    for settings in invalid {
        let chip = Chip::new(1, &air);
        let outcome = Sx127x::new(Bus(chip.clone()), ResetPin(chip.clone()), NoDelay, settings);
        assert!(
            matches!(outcome, Err(RadioError::InvalidConfig)),
            "{settings:?}"
        );
        assert_eq!(chip.borrow().transactions, 0);
        assert_eq!(chip.borrow().resets, 0);
    }
}

#[test]
fn a_signed_fragment_crosses_the_radio_and_reassembles() {
    use arxia_transport::{fragment, Fragment, Reassembler};

    let air = Rc::new(RefCell::new(Air::default()));
    let mut a = station(1, &air, config());
    let mut b = station(2, &air, config());
    b.radio.start_receive().unwrap();

    // A message longer than one packet, split for the radio's limit.
    let (key, _) = arxia_crypto::generate_keypair();
    let message: Vec<u8> = (0..600).map(|i| (i % 253) as u8).collect();
    let pieces = fragment(&key, [3; 16], &message, MAX_PAYLOAD_LEN).unwrap();
    assert_eq!(pieces.len(), 5);

    let mut reassembler = Reassembler::new();
    let mut whole = None;
    let mut buffer = [0u8; MAX_PAYLOAD_LEN];
    for piece in &pieces {
        a.radio.transmit(&piece.to_bytes(), 1_000).unwrap();
        propagate(&air, &[&a, &b]);
        let received = b
            .radio
            .poll_receive(&mut buffer)
            .unwrap()
            .expect("a packet");
        let heard = Fragment::from_bytes(&buffer[..received.len]).unwrap();
        if let Some(complete) = reassembler.feed(heard).unwrap() {
            whole = Some(complete);
        }
    }
    assert_eq!(whole, Some(message));
    assert!(a.chip.borrow().violations.is_empty());
    assert!(b.chip.borrow().violations.is_empty());
}
