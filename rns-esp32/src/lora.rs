//! SX1262 LoRa radio interface for Heltec WiFi LoRa 32 V3.
//!
//! Half-duplex: reader keeps radio in continuous RX. Writer briefly locks,
//! switches to TX, sends, then returns to RX. Each LoRa packet = one
//! Reticulum frame (no HDLC/KISS framing).

use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use esp_idf_hal::gpio::{AnyIOPin, Input, Output, PinDriver};
use esp_idf_hal::spi::{self, SpiDeviceDriver, SpiDriver, SpiDriverConfig};
use esp_idf_hal::units::Hertz;

use crate::config;

// SX1262 opcodes
const OPCODE_SET_STANDBY: u8 = 0x80;
const OPCODE_SET_PACKET_TYPE: u8 = 0x8A;
const OPCODE_SET_RF_FREQUENCY: u8 = 0x86;
const OPCODE_SET_PA_CONFIG: u8 = 0x95;
const OPCODE_SET_TX_PARAMS: u8 = 0x8E;
const OPCODE_SET_MODULATION_PARAMS: u8 = 0x8B;
const OPCODE_SET_PACKET_PARAMS: u8 = 0x8C;
const OPCODE_SET_BUFFER_BASE_ADDRESS: u8 = 0x8F;
const OPCODE_WRITE_BUFFER: u8 = 0x0E;
const OPCODE_READ_BUFFER: u8 = 0x1E;
const OPCODE_SET_DIO_IRQ_PARAMS: u8 = 0x08;
const OPCODE_GET_IRQ_STATUS: u8 = 0x12;
const OPCODE_CLEAR_IRQ_STATUS: u8 = 0x02;
const OPCODE_SET_RX: u8 = 0x82;
const OPCODE_SET_TX: u8 = 0x83;
const OPCODE_GET_RX_BUFFER_STATUS: u8 = 0x13;
const OPCODE_SET_DIO3_AS_TCXO_CTRL: u8 = 0x97;
const OPCODE_CALIBRATE: u8 = 0x89;
const OPCODE_SET_REGULATOR_MODE: u8 = 0x96;

// IRQ masks
const IRQ_TX_DONE: u16 = 0x0001;
const IRQ_RX_DONE: u16 = 0x0002;
const IRQ_CRC_ERR: u16 = 0x0040;
const IRQ_TIMEOUT: u16 = 0x0200;

// Standby modes
const STANDBY_RC: u8 = 0x00;

// Packet type
const PACKET_TYPE_LORA: u8 = 0x01;

/// Opaque handle to the SX1262 radio behind a mutex.
pub struct Radio {
    spi: SpiDeviceDriver<'static, SpiDriver<'static>>,
    cs: PinDriver<'static, AnyIOPin, Output>,
    rst: PinDriver<'static, AnyIOPin, Output>,
    busy: PinDriver<'static, AnyIOPin, Input>,
    dio1: PinDriver<'static, AnyIOPin, Input>,
}

impl Radio {
    /// Wait until the BUSY pin goes low (radio ready).
    fn wait_busy(&self) {
        while self.busy.is_high() {
            thread::sleep(Duration::from_micros(100));
        }
    }

    /// Execute an SPI command (opcode + params), no response read.
    fn cmd(&mut self, opcode: u8, params: &[u8]) {
        self.wait_busy();
        let mut buf = Vec::with_capacity(1 + params.len());
        buf.push(opcode);
        buf.extend_from_slice(params);

        self.cs.set_low().ok();
        let _ = self.spi.write(&buf);
        self.cs.set_high().ok();
    }

    /// Execute an SPI command and read `resp_len` response bytes.
    fn cmd_read(&mut self, opcode: u8, params: &[u8], resp_len: usize) -> Vec<u8> {
        self.wait_busy();
        // TX: opcode + params + NOP byte (status) + NOP bytes for response
        let tx_len = 1 + params.len() + 1 + resp_len;
        let mut tx = vec![0u8; tx_len];
        tx[0] = opcode;
        tx[1..1 + params.len()].copy_from_slice(params);
        let mut rx = vec![0u8; tx_len];

        self.cs.set_low().ok();
        let _ = self.spi.transfer(&mut rx, &tx);
        self.cs.set_high().ok();

        // Response starts after opcode + params + status byte
        let start = 1 + params.len() + 1;
        rx[start..].to_vec()
    }

    /// Hardware reset the radio.
    fn reset(&mut self) {
        self.rst.set_low().ok();
        thread::sleep(Duration::from_millis(10));
        self.rst.set_high().ok();
        thread::sleep(Duration::from_millis(20));
        self.wait_busy();
    }

    /// Set standby mode (RC oscillator).
    fn set_standby(&mut self) {
        self.cmd(OPCODE_SET_STANDBY, &[STANDBY_RC]);
    }

    /// Configure TCXO on DIO3 (Heltec V3 uses TCXO at 1.8V).
    fn set_dio3_tcxo(&mut self) {
        // voltage = 0x02 (1.8V), timeout = 320 * 15.625us ≈ 5ms
        self.cmd(OPCODE_SET_DIO3_AS_TCXO_CTRL, &[0x02, 0x00, 0x01, 0x40]);
    }

    /// Calibrate all blocks.
    fn calibrate(&mut self) {
        self.cmd(OPCODE_CALIBRATE, &[0x7F]);
        thread::sleep(Duration::from_millis(10));
    }

    /// Set regulator mode to DC-DC.
    fn set_regulator_dc_dc(&mut self) {
        self.cmd(OPCODE_SET_REGULATOR_MODE, &[0x01]);
    }

    /// Configure radio for LoRa operation.
    fn configure(&mut self) {
        self.set_standby();
        self.set_dio3_tcxo();
        self.calibrate();
        self.set_regulator_dc_dc();

        // Set packet type to LoRa
        self.cmd(OPCODE_SET_PACKET_TYPE, &[PACKET_TYPE_LORA]);

        // Set RF frequency
        let frf = ((config::LORA_FREQUENCY as u64) << 25) / 32_000_000;
        self.cmd(OPCODE_SET_RF_FREQUENCY, &[
            (frf >> 24) as u8,
            (frf >> 16) as u8,
            (frf >> 8) as u8,
            frf as u8,
        ]);

        // PA config for SX1262: paDutyCycle=0x04, hpMax=0x07, deviceSel=0x00 (SX1262), paLut=0x01
        self.cmd(OPCODE_SET_PA_CONFIG, &[0x04, 0x07, 0x00, 0x01]);

        // TX params: power, rampTime (0x04 = 200us)
        self.cmd(OPCODE_SET_TX_PARAMS, &[config::LORA_TX_POWER as u8, 0x04]);

        // Modulation params: SF, BW, CR, LowDataRateOptimize
        let bw_param = match config::LORA_BANDWIDTH {
            7_800 => 0x00,
            10_400 => 0x08,
            15_600 => 0x01,
            20_800 => 0x09,
            31_250 => 0x02,
            41_700 => 0x0A,
            62_500 => 0x03,
            125_000 => 0x04,
            250_000 => 0x05,
            500_000 => 0x06,
            _ => 0x04, // default 125kHz
        };
        let ldro = if config::LORA_SPREADING_FACTOR >= 11 && config::LORA_BANDWIDTH <= 125_000 {
            0x01
        } else {
            0x00
        };
        self.cmd(OPCODE_SET_MODULATION_PARAMS, &[
            config::LORA_SPREADING_FACTOR,
            bw_param,
            config::LORA_CODING_RATE - 4, // CR encoding: 1=4/5, 2=4/6, etc.
            ldro,
        ]);

        // Buffer base addresses: TX=0, RX=128
        self.cmd(OPCODE_SET_BUFFER_BASE_ADDRESS, &[0x00, 0x80]);

        // DIO1 IRQ: map TxDone + RxDone + CrcErr + Timeout to DIO1
        let irq_mask = IRQ_TX_DONE | IRQ_RX_DONE | IRQ_CRC_ERR | IRQ_TIMEOUT;
        self.cmd(OPCODE_SET_DIO_IRQ_PARAMS, &[
            (irq_mask >> 8) as u8, irq_mask as u8,   // IRQ mask
            (irq_mask >> 8) as u8, irq_mask as u8,   // DIO1 mask
            0x00, 0x00,                                // DIO2 mask
            0x00, 0x00,                                // DIO3 mask
        ]);
    }

    /// Set packet params for RX mode (max payload length, explicit header, CRC).
    fn set_rx_packet_params(&mut self) {
        let crc = if config::LORA_CRC_ON { 0x01 } else { 0x00 };
        self.cmd(OPCODE_SET_PACKET_PARAMS, &[
            (config::LORA_PREAMBLE_LENGTH >> 8) as u8,
            config::LORA_PREAMBLE_LENGTH as u8,
            0x00, // explicit header
            config::LORA_MTU as u8, // max payload length for RX
            crc,
            0x00, // standard IQ
        ]);
    }

    /// Enter continuous RX mode with proper packet params.
    fn set_rx_continuous(&mut self) {
        self.set_rx_packet_params();
        // timeout = 0xFFFFFF means continuous
        self.cmd(OPCODE_SET_RX, &[0xFF, 0xFF, 0xFF]);
    }

    /// Get IRQ status.
    fn get_irq_status(&mut self) -> u16 {
        let resp = self.cmd_read(OPCODE_GET_IRQ_STATUS, &[], 2);
        ((resp[0] as u16) << 8) | resp[1] as u16
    }

    /// Clear IRQ flags.
    fn clear_irq(&mut self, mask: u16) {
        self.cmd(OPCODE_CLEAR_IRQ_STATUS, &[(mask >> 8) as u8, mask as u8]);
    }

    /// Transmit a frame. Sets packet params, writes buffer, triggers TX, waits for TxDone.
    fn transmit(&mut self, data: &[u8]) -> std::io::Result<()> {
        if data.len() > config::LORA_MTU as usize {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "frame exceeds LoRa MTU",
            ));
        }

        self.set_standby();

        // Packet params: preamble(2), header=explicit(0), payloadLen, CRC, invertIQ=standard(0)
        let crc = if config::LORA_CRC_ON { 0x01 } else { 0x00 };
        self.cmd(OPCODE_SET_PACKET_PARAMS, &[
            (config::LORA_PREAMBLE_LENGTH >> 8) as u8,
            config::LORA_PREAMBLE_LENGTH as u8,
            0x00, // explicit header
            data.len() as u8,
            crc,
            0x00, // standard IQ
        ]);

        // Write data to TX buffer at offset 0
        let mut buf = Vec::with_capacity(1 + data.len());
        buf.push(0x00); // offset
        buf.extend_from_slice(data);
        self.cmd(OPCODE_WRITE_BUFFER, &buf);

        // Clear all IRQs and start TX (no timeout)
        self.clear_irq(0xFFFF);
        self.cmd(OPCODE_SET_TX, &[0x00, 0x00, 0x00]);

        // Wait for TxDone or timeout
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        loop {
            if std::time::Instant::now() > deadline {
                self.set_standby();
                return Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "TX timeout",
                ));
            }
            let irq = self.get_irq_status();
            if irq & IRQ_TX_DONE != 0 {
                self.clear_irq(IRQ_TX_DONE);
                break;
            }
            thread::sleep(Duration::from_millis(1));
        }

        Ok(())
    }

    /// Try to receive a frame. Returns Some(data) if RxDone, None otherwise.
    fn try_receive(&mut self) -> Option<Vec<u8>> {
        let irq = self.get_irq_status();

        if irq & IRQ_RX_DONE != 0 {
            self.clear_irq(IRQ_RX_DONE);

            if irq & IRQ_CRC_ERR != 0 {
                self.clear_irq(IRQ_CRC_ERR);
                log::warn!("LoRa RX CRC error, dropping");
                return None;
            }

            // Get RX buffer status: [payloadLen, rxStartBufferPointer]
            let status = self.cmd_read(OPCODE_GET_RX_BUFFER_STATUS, &[], 2);
            let len = status[0] as usize;
            let offset = status[1];

            if len == 0 || len > config::LORA_MTU as usize {
                log::warn!("LoRa RX invalid len={}", len);
                return None;
            }

            // Read buffer
            let data = self.cmd_read(OPCODE_READ_BUFFER, &[offset], len);
            Some(data)
        } else {
            if irq & IRQ_CRC_ERR != 0 {
                self.clear_irq(IRQ_CRC_ERR);
                log::warn!("LoRa CRC error (no RxDone)");
            }
            if irq & IRQ_TIMEOUT != 0 {
                self.clear_irq(IRQ_TIMEOUT);
            }
            None
        }
    }
}

/// Shared radio handle.
pub type SharedRadio = Arc<Mutex<Radio>>;

/// Writer end: sends frames over LoRa.
pub struct LoRaWriter {
    radio: SharedRadio,
}

impl LoRaWriter {
    pub fn send_frame(&mut self, data: &[u8]) -> std::io::Result<()> {
        let mut radio = self.radio.lock().unwrap();
        let result = radio.transmit(data);
        // Return to RX after transmitting
        radio.set_rx_continuous();
        result
    }
}

/// Initialize the SX1262 radio and return (SharedRadio, LoRaWriter).
///
/// The caller should spawn a reader thread using `reader_loop()`.
pub fn init(
    spi_driver: SpiDriver<'static>,
    cs: PinDriver<'static, AnyIOPin, Output>,
    rst: PinDriver<'static, AnyIOPin, Output>,
    busy: PinDriver<'static, AnyIOPin, Input>,
    dio1: PinDriver<'static, AnyIOPin, Input>,
) -> std::io::Result<(SharedRadio, LoRaWriter)> {
    let spi_config = spi::config::Config::new()
        .baudrate(Hertz(2_000_000))
        .data_mode(esp_idf_hal::spi::config::MODE_0);

    let spi_device = SpiDeviceDriver::new(spi_driver, Option::<AnyIOPin>::None, &spi_config)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, format!("SPI init: {e}")))?;

    let mut radio = Radio {
        spi: spi_device,
        cs,
        rst,
        busy,
        dio1,
    };

    radio.reset();
    radio.configure();
    radio.set_rx_continuous();

    log::info!("SX1262 initialized: freq={}Hz, SF={}, BW={}Hz, TX={}dBm",
        config::LORA_FREQUENCY, config::LORA_SPREADING_FACTOR,
        config::LORA_BANDWIDTH, config::LORA_TX_POWER);

    let shared = Arc::new(Mutex::new(radio));
    let writer = LoRaWriter { radio: shared.clone() };

    Ok((shared, writer))
}

/// Reader loop: polls for received frames and sends them to the event channel.
/// Run this in a dedicated thread.
pub fn reader_loop(
    radio: SharedRadio,
    tx: std::sync::mpsc::Sender<crate::driver::Event>,
    interface_id: rns_core::transport::types::InterfaceId,
) {
    log::info!("LoRa reader loop started");
    loop {
        let frame = {
            let mut r = radio.lock().unwrap();
            r.try_receive()
        };

        if let Some(data) = frame {
            log::info!("LoRa RX: {} bytes", data.len());
            if tx.send(crate::driver::Event::Frame {
                interface_id,
                data,
            }).is_err() {
                log::warn!("LoRa reader: event channel closed, exiting");
                break;
            }
        }

        // Poll interval — balance between latency and CPU usage
        thread::sleep(Duration::from_millis(10));
    }
}
