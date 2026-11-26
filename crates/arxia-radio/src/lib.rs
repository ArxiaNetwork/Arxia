//! Blocking LoRa driver for the Semtech SX1276 family (SX1276 to
//! SX1279), the radio of T-Beam class boards.
//!
//! The driver is generic over `embedded-hal` 1.0: an SPI device, a
//! reset pin and a delay. It knows nothing about a particular board
//! and uses no interrupt line: completion of a transmission and
//! arrival of a packet are read from the interrupt flag register.
//!
//! # What it does
//!
//! - [`Sx127x::new`] resets the chip, checks its version register and
//!   applies a [`RadioConfig`].
//! - [`Sx127x::transmit`] sends one packet of at most
//!   [`MAX_PAYLOAD_LEN`] bytes and returns when the chip reports it
//!   sent, or after a bounded wait.
//! - [`Sx127x::start_receive`] puts the chip in continuous receive;
//!   [`Sx127x::poll_receive`] returns a packet if one arrived with a
//!   valid checksum.
//!
//! # Regulation
//!
//! Frequency, power and time on air are the caller's responsibility.
//! The licence-free bands differ by region, and so do their limits on
//! power and duty cycle. There is no default frequency: a
//! [`RadioConfig`] cannot be built without one.
//!
//! # Checked against
//!
//! Register addresses, mode values and interrupt masks follow the
//! SX1276/77/78/79 datasheet. The crate is tested on hosts against a
//! register-level model of the chip (`tests/model.rs`); that model
//! encodes the same reading of the datasheet, so it checks the
//! driver's logic, not the chip. The driver has not been run on
//! hardware yet.

#![no_std]
#![deny(unsafe_code)]
#![warn(missing_docs)]

use embedded_hal::delay::DelayNs;
use embedded_hal::digital::OutputPin;
use embedded_hal::spi::{Operation, SpiDevice};

/// Largest payload of one LoRa packet, in bytes.
pub const MAX_PAYLOAD_LEN: usize = 255;

/// Value of the version register on the SX1276 family.
pub const CHIP_VERSION: u8 = 0x12;

/// Crystal frequency the frequency registers are scaled by.
const FXOSC_HZ: u64 = 32_000_000;

/// Register addresses.
mod reg {
    pub const FIFO: u8 = 0x00;
    pub const OP_MODE: u8 = 0x01;
    pub const FRF_MSB: u8 = 0x06;
    pub const FRF_MID: u8 = 0x07;
    pub const FRF_LSB: u8 = 0x08;
    pub const PA_CONFIG: u8 = 0x09;
    pub const OCP: u8 = 0x0b;
    pub const LNA: u8 = 0x0c;
    pub const FIFO_ADDR_PTR: u8 = 0x0d;
    pub const FIFO_TX_BASE_ADDR: u8 = 0x0e;
    pub const FIFO_RX_BASE_ADDR: u8 = 0x0f;
    pub const FIFO_RX_CURRENT_ADDR: u8 = 0x10;
    pub const IRQ_FLAGS: u8 = 0x12;
    pub const RX_NB_BYTES: u8 = 0x13;
    pub const PKT_SNR_VALUE: u8 = 0x19;
    pub const PKT_RSSI_VALUE: u8 = 0x1a;
    pub const MODEM_CONFIG_1: u8 = 0x1d;
    pub const MODEM_CONFIG_2: u8 = 0x1e;
    pub const PREAMBLE_MSB: u8 = 0x20;
    pub const PREAMBLE_LSB: u8 = 0x21;
    pub const PAYLOAD_LENGTH: u8 = 0x22;
    pub const MODEM_CONFIG_3: u8 = 0x26;
    pub const DETECTION_OPTIMIZE: u8 = 0x31;
    pub const DETECTION_THRESHOLD: u8 = 0x37;
    pub const SYNC_WORD: u8 = 0x39;
    pub const VERSION: u8 = 0x42;
    pub const PA_DAC: u8 = 0x4d;
}

/// Operating mode register: LoRa mode bit and the modes used here.
mod mode {
    pub const LONG_RANGE: u8 = 0x80;
    pub const SLEEP: u8 = 0x00;
    pub const STANDBY: u8 = 0x01;
    pub const TX: u8 = 0x03;
    pub const RX_CONTINUOUS: u8 = 0x05;
    pub const MASK: u8 = 0x07;
}

/// Interrupt flag register bits.
mod irq {
    pub const RX_DONE: u8 = 0x40;
    pub const PAYLOAD_CRC_ERROR: u8 = 0x20;
    pub const TX_DONE: u8 = 0x08;
    pub const ALL: u8 = 0xff;
}

/// LoRa signal bandwidth.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bandwidth {
    /// 125 kHz.
    Khz125,
    /// 250 kHz.
    Khz250,
    /// 500 kHz.
    Khz500,
}

impl Bandwidth {
    fn bits(self) -> u8 {
        match self {
            Self::Khz125 => 7,
            Self::Khz250 => 8,
            Self::Khz500 => 9,
        }
    }

    /// Bandwidth in hertz.
    pub fn hz(self) -> u32 {
        match self {
            Self::Khz125 => 125_000,
            Self::Khz250 => 250_000,
            Self::Khz500 => 500_000,
        }
    }
}

/// Radio settings. Two radios exchange packets only if frequency,
/// spreading factor, bandwidth, coding rate and sync word all match.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RadioConfig {
    /// Carrier frequency in hertz. The driver uses the high-frequency
    /// port of the chip: 779 MHz to 1020 MHz.
    pub frequency_hz: u32,
    /// Spreading factor, 7 to 12.
    pub spreading_factor: u8,
    /// Signal bandwidth.
    pub bandwidth: Bandwidth,
    /// Coding rate denominator: 5 to 8, for 4/5 to 4/8.
    pub coding_rate: u8,
    /// Transmit power on the PA_BOOST pin, 2 to 17 dBm.
    pub tx_power_dbm: i8,
    /// Preamble length in symbols, at least 6.
    pub preamble_symbols: u16,
    /// Sync word. Radios with different sync words ignore each other.
    pub sync_word: u8,
}

impl RadioConfig {
    /// Settings at `frequency_hz` with a common long-range profile:
    /// spreading factor 9, 125 kHz, coding rate 4/5, 14 dBm, preamble
    /// of 8 symbols, and a private sync word. The caller remains
    /// responsible for the frequency and power being lawful where the
    /// device operates.
    pub const fn at(frequency_hz: u32) -> Self {
        Self {
            frequency_hz,
            spreading_factor: 9,
            bandwidth: Bandwidth::Khz125,
            coding_rate: 5,
            tx_power_dbm: 14,
            preamble_symbols: 8,
            sync_word: 0x2b,
        }
    }

    fn is_valid(&self) -> bool {
        (779_000_000..=1_020_000_000).contains(&self.frequency_hz)
            && (7..=12).contains(&self.spreading_factor)
            && (5..=8).contains(&self.coding_rate)
            && (2..=17).contains(&self.tx_power_dbm)
            && self.preamble_symbols >= 6
    }

    /// Duration of one symbol, in microseconds.
    pub fn symbol_micros(&self) -> u32 {
        (1_000_000u64 * (1u64 << self.spreading_factor) / u64::from(self.bandwidth.hz())) as u32
    }
}

/// What can go wrong when driving the radio.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RadioError<SpiError, PinError> {
    /// The SPI bus reported an error.
    Spi(SpiError),
    /// The reset pin reported an error.
    Pin(PinError),
    /// The version register did not read [`CHIP_VERSION`]: no chip, a
    /// different chip, or wrong wiring.
    VersionMismatch(u8),
    /// A setting is outside the range documented on [`RadioConfig`].
    InvalidConfig,
    /// The payload is empty or longer than [`MAX_PAYLOAD_LEN`].
    PayloadLength(usize),
    /// The chip did not report the packet sent within the wait given.
    TxTimeout,
}

/// A received packet: its length in the caller's buffer and the
/// signal figures the chip measured for it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Received {
    /// Number of payload bytes written to the buffer.
    pub len: usize,
    /// Received signal strength of the packet, in dBm.
    pub rssi_dbm: i16,
    /// Signal-to-noise ratio of the packet, in quarter decibels.
    pub snr_quarter_db: i8,
}

/// An SX1276-family radio in LoRa mode.
pub struct Sx127x<SPI, RST, DELAY> {
    spi: SPI,
    reset: RST,
    delay: DELAY,
    config: RadioConfig,
}

impl<SPI, RST, DELAY> Sx127x<SPI, RST, DELAY>
where
    SPI: SpiDevice,
    RST: OutputPin,
    DELAY: DelayNs,
{
    /// Reset the chip, check that it is an SX1276-family part, and
    /// apply `config`. The radio is left in standby.
    ///
    /// # Errors
    ///
    /// - [`RadioError::InvalidConfig`] before anything is sent to the
    ///   chip, if `config` is out of range.
    /// - [`RadioError::VersionMismatch`] if the chip does not answer
    ///   as expected.
    /// - Bus and pin errors.
    pub fn new(
        spi: SPI,
        reset: RST,
        delay: DELAY,
        config: RadioConfig,
    ) -> Result<Self, RadioError<SPI::Error, RST::Error>> {
        if !config.is_valid() {
            return Err(RadioError::InvalidConfig);
        }
        let mut radio = Self {
            spi,
            reset,
            delay,
            config,
        };
        radio.reset.set_low().map_err(RadioError::Pin)?;
        radio.delay.delay_ms(10);
        radio.reset.set_high().map_err(RadioError::Pin)?;
        radio.delay.delay_ms(10);

        let version = radio.read(reg::VERSION)?;
        if version != CHIP_VERSION {
            return Err(RadioError::VersionMismatch(version));
        }
        radio.configure()?;
        Ok(radio)
    }

    /// The settings the radio was configured with.
    pub fn config(&self) -> &RadioConfig {
        &self.config
    }

    /// Give back the bus, the reset pin and the delay.
    pub fn release(self) -> (SPI, RST, DELAY) {
        (self.spi, self.reset, self.delay)
    }

    fn configure(&mut self) -> Result<(), RadioError<SPI::Error, RST::Error>> {
        let config = self.config;
        // The LoRa mode bit can only be changed in sleep, and the chip
        // leaves reset in standby: go to sleep first, in the mode it is
        // in, then set the bit.
        self.write(reg::OP_MODE, mode::SLEEP)?;
        self.delay.delay_ms(10);
        self.write(reg::OP_MODE, mode::LONG_RANGE | mode::SLEEP)?;
        self.delay.delay_ms(10);

        let frf = (u64::from(config.frequency_hz) << 19) / FXOSC_HZ;
        self.write(reg::FRF_MSB, (frf >> 16) as u8)?;
        self.write(reg::FRF_MID, (frf >> 8) as u8)?;
        self.write(reg::FRF_LSB, frf as u8)?;

        // The whole FIFO for whichever direction is in use.
        self.write(reg::FIFO_TX_BASE_ADDR, 0)?;
        self.write(reg::FIFO_RX_BASE_ADDR, 0)?;

        // Highest LNA gain with the HF boost.
        let lna = self.read(reg::LNA)?;
        self.write(reg::LNA, lna | 0x03)?;

        // Bandwidth, coding rate, explicit header.
        self.write(
            reg::MODEM_CONFIG_1,
            (config.bandwidth.bits() << 4) | ((config.coding_rate - 4) << 1),
        )?;
        // Spreading factor, payload CRC on.
        self.write(reg::MODEM_CONFIG_2, (config.spreading_factor << 4) | 0x04)?;
        // Automatic gain control; low data rate optimisation when a
        // symbol lasts more than 16 ms, as the datasheet requires.
        let low_data_rate = config.symbol_micros() > 16_000;
        self.write(
            reg::MODEM_CONFIG_3,
            0x04 | if low_data_rate { 0x08 } else { 0x00 },
        )?;
        // Detection settings for spreading factors 7 to 12.
        self.write(reg::DETECTION_OPTIMIZE, 0xc3)?;
        self.write(reg::DETECTION_THRESHOLD, 0x0a)?;

        self.write(reg::PREAMBLE_MSB, (config.preamble_symbols >> 8) as u8)?;
        self.write(reg::PREAMBLE_LSB, config.preamble_symbols as u8)?;
        self.write(reg::SYNC_WORD, config.sync_word)?;

        // PA_BOOST output, 2 to 17 dBm: output power = 2 + setting.
        // Default PA DAC, over-current protection at 100 mA.
        self.write(reg::PA_DAC, 0x84)?;
        self.write(reg::OCP, 0x20 | 0x0b)?;
        self.write(reg::PA_CONFIG, 0x80 | (config.tx_power_dbm - 2) as u8)?;

        self.write(reg::IRQ_FLAGS, irq::ALL)?;
        self.set_mode(mode::STANDBY)
    }

    /// Send one packet and wait until the chip reports it sent.
    ///
    /// `timeout_ms` bounds the wait; it should exceed the time on air
    /// of the packet with the configured settings. The radio is left
    /// in standby: call [`Sx127x::start_receive`] to listen again.
    ///
    /// # Errors
    ///
    /// - [`RadioError::PayloadLength`] if `payload` is empty or longer
    ///   than [`MAX_PAYLOAD_LEN`]; nothing is transmitted.
    /// - [`RadioError::TxTimeout`] if the chip does not report
    ///   completion in time. The radio is put back in standby.
    pub fn transmit(
        &mut self,
        payload: &[u8],
        timeout_ms: u32,
    ) -> Result<(), RadioError<SPI::Error, RST::Error>> {
        if payload.is_empty() || payload.len() > MAX_PAYLOAD_LEN {
            return Err(RadioError::PayloadLength(payload.len()));
        }
        self.set_mode(mode::STANDBY)?;
        self.write(reg::IRQ_FLAGS, irq::ALL)?;
        self.write(reg::FIFO_ADDR_PTR, 0)?;
        self.spi
            .transaction(&mut [
                Operation::Write(&[reg::FIFO | 0x80]),
                Operation::Write(payload),
            ])
            .map_err(RadioError::Spi)?;
        self.write(reg::PAYLOAD_LENGTH, payload.len() as u8)?;
        self.set_mode(mode::TX)?;

        for _ in 0..timeout_ms {
            if self.read(reg::IRQ_FLAGS)? & irq::TX_DONE != 0 {
                self.write(reg::IRQ_FLAGS, irq::TX_DONE)?;
                return Ok(());
            }
            self.delay.delay_ms(1);
        }
        self.set_mode(mode::STANDBY)?;
        Err(RadioError::TxTimeout)
    }

    /// Listen continuously. Packets are collected with
    /// [`Sx127x::poll_receive`].
    ///
    /// # Errors
    ///
    /// Bus errors.
    pub fn start_receive(&mut self) -> Result<(), RadioError<SPI::Error, RST::Error>> {
        self.set_mode(mode::STANDBY)?;
        self.write(reg::IRQ_FLAGS, irq::ALL)?;
        self.write(reg::FIFO_ADDR_PTR, 0)?;
        self.set_mode(mode::RX_CONTINUOUS)
    }

    /// Return a packet if one has arrived since the last call.
    ///
    /// A packet whose checksum failed is dropped and reported as no
    /// packet. `buffer` must hold [`MAX_PAYLOAD_LEN`] bytes to take
    /// any packet; a longer packet than the buffer is truncated to it.
    /// The radio keeps listening.
    ///
    /// # Errors
    ///
    /// Bus errors.
    pub fn poll_receive(
        &mut self,
        buffer: &mut [u8],
    ) -> Result<Option<Received>, RadioError<SPI::Error, RST::Error>> {
        let flags = self.read(reg::IRQ_FLAGS)?;
        if flags & irq::RX_DONE == 0 {
            return Ok(None);
        }
        self.write(reg::IRQ_FLAGS, irq::ALL)?;
        if flags & irq::PAYLOAD_CRC_ERROR != 0 {
            return Ok(None);
        }
        let len = usize::from(self.read(reg::RX_NB_BYTES)?).min(buffer.len());
        let start = self.read(reg::FIFO_RX_CURRENT_ADDR)?;
        self.write(reg::FIFO_ADDR_PTR, start)?;
        self.spi
            .transaction(&mut [
                Operation::Write(&[reg::FIFO & 0x7f]),
                Operation::Read(&mut buffer[..len]),
            ])
            .map_err(RadioError::Spi)?;
        // High-frequency port: RSSI in dBm is the register minus 157.
        let rssi_dbm = i16::from(self.read(reg::PKT_RSSI_VALUE)?) - 157;
        let snr_quarter_db = self.read(reg::PKT_SNR_VALUE)? as i8;
        Ok(Some(Received {
            len,
            rssi_dbm,
            snr_quarter_db,
        }))
    }

    /// Put the radio in sleep, its lowest power state. The settings
    /// are kept.
    ///
    /// # Errors
    ///
    /// Bus errors.
    pub fn sleep(&mut self) -> Result<(), RadioError<SPI::Error, RST::Error>> {
        self.set_mode(mode::SLEEP)
    }

    fn set_mode(&mut self, to: u8) -> Result<(), RadioError<SPI::Error, RST::Error>> {
        self.write(reg::OP_MODE, mode::LONG_RANGE | (to & mode::MASK))
    }

    fn read(&mut self, register: u8) -> Result<u8, RadioError<SPI::Error, RST::Error>> {
        let mut value = [0u8];
        self.spi
            .transaction(&mut [
                Operation::Write(&[register & 0x7f]),
                Operation::Read(&mut value),
            ])
            .map_err(RadioError::Spi)?;
        Ok(value[0])
    }

    fn write(&mut self, register: u8, value: u8) -> Result<(), RadioError<SPI::Error, RST::Error>> {
        self.spi
            .transaction(&mut [Operation::Write(&[register | 0x80, value])])
            .map_err(RadioError::Spi)
    }
}
