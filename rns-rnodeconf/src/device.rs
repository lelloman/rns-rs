//! An RNode on a serial port: the command frames upstream `rnodeconf.py`'s
//! `RNode` class writes, and a port of its `readLoop`, which collects the
//! device's replies in the background.

use std::io::{Read, Write};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use crate::kiss::{self, *};

/// What the device has reported so far.
#[derive(Debug, Default, Clone)]
pub struct Reported {
    pub detected: Option<bool>,
    pub major_version: Option<u8>,
    pub minor_version: Option<u8>,
    pub platform: Option<u8>,
    pub mcu: Option<u8>,
    pub board: Option<u8>,
    pub device_hash: Option<Vec<u8>>,
    pub firmware_hash_target: Option<Vec<u8>>,
    pub firmware_hash: Option<Vec<u8>>,
    pub eeprom: Option<Vec<u8>>,
    pub cfg_sector: Option<Vec<u8>>,
    pub r_frequency: Option<u32>,
    pub r_bandwidth: Option<u32>,
    pub r_txpower: Option<u8>,
    pub r_sf: Option<u8>,
    pub r_cr: Option<u8>,
    pub r_state: Option<u8>,
    pub r_lock: Option<u8>,
    pub r_bt_pin: Option<u32>,
}

impl Reported {
    /// upstream `updateVersion`: `major.minor`, the minor part two digits.
    pub fn version(&self) -> Option<String> {
        Some(format!(
            "{}.{:02}",
            self.major_version?, self.minor_version?
        ))
    }
}

pub struct RNode {
    writer: std::fs::File,
    pub state: Arc<Mutex<Reported>>,
}

impl RNode {
    /// Start reading `reader` in the background.
    pub fn new(reader: std::fs::File, writer: std::fs::File) -> Self {
        let state = Arc::new(Mutex::new(Reported::default()));
        let shared = Arc::clone(&state);
        thread::Builder::new()
            .name("rnode-read".into())
            .spawn(move || read_loop(reader, shared))
            .expect("spawn serial reader");
        Self { writer, state }
    }

    pub fn reported(&self) -> Reported {
        self.state.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }

    fn update(&self, f: impl FnOnce(&mut Reported)) {
        f(&mut self.state.lock().unwrap_or_else(|e| e.into_inner()));
    }

    pub fn write(&mut self, bytes: &[u8], what: &str) -> std::io::Result<()> {
        self.writer
            .write_all(bytes)
            .and_then(|_| self.writer.flush())
            .map_err(|e| {
                std::io::Error::new(e.kind(), format!("An IO error occurred while {what}"))
            })
    }

    /// upstream `detect`.
    pub fn detect(&mut self) -> std::io::Result<()> {
        let command = [
            FEND,
            CMD_DETECT,
            DETECT_REQ,
            FEND,
            CMD_FW_VERSION,
            0x00,
            FEND,
            CMD_PLATFORM,
            0x00,
            FEND,
            CMD_MCU,
            0x00,
            FEND,
            CMD_BOARD,
            0x00,
            FEND,
            CMD_DEV_HASH,
            0x01,
            FEND,
            CMD_HASHES,
            0x01,
            FEND,
            CMD_HASHES,
            0x02,
            FEND,
        ];
        self.write(&command, "detecting hardware")
    }

    /// upstream `leave`, which waits a second after.
    pub fn leave(&mut self) -> std::io::Result<()> {
        self.write(
            &[FEND, CMD_LEAVE, 0xFF, FEND],
            "sending host left command to device",
        )?;
        thread::sleep(Duration::from_secs(1));
        Ok(())
    }

    /// upstream `device_probe`: wait for the board to boot, ask it to
    /// identify itself, and wait for its answer.
    pub fn device_probe(&mut self) -> std::io::Result<()> {
        thread::sleep(Duration::from_millis(2500));
        self.detect()?;
        thread::sleep(Duration::from_millis(750));
        if self.reported().detected == Some(true) {
            Ok(())
        } else {
            Err(std::io::Error::other(
                "Got invalid response while detecting device",
            ))
        }
    }

    /// upstream `download_eeprom`, without parsing.
    pub fn download_eeprom(&mut self) -> std::io::Result<Option<Vec<u8>>> {
        self.update(|r| r.eeprom = None);
        self.write(&[FEND, CMD_ROM_READ, 0x00, FEND], "downloading EEPROM")?;
        thread::sleep(Duration::from_millis(600));
        Ok(self.reported().eeprom)
    }

    /// upstream `download_cfg_sector`.
    pub fn download_cfg_sector(&mut self) -> std::io::Result<Option<Vec<u8>>> {
        self.update(|r| r.cfg_sector = None);
        self.write(
            &[FEND, CMD_CFG_READ, 0x00, FEND],
            "downloading config sector",
        )?;
        thread::sleep(Duration::from_millis(600));
        Ok(self.reported().cfg_sector)
    }

    fn u32_command(&mut self, command: u8, value: u32, what: &str) -> std::io::Result<()> {
        self.write(&kiss::frame(command, &value.to_be_bytes()), what)
    }

    /// upstream `initRadio`.
    pub fn init_radio(&mut self, radio: &RadioConfig) -> std::io::Result<()> {
        self.u32_command(CMD_FREQUENCY, radio.frequency, "configuring frequency")?;
        self.u32_command(CMD_BANDWIDTH, radio.bandwidth, "configuring bandwidth")?;
        self.write(
            &[FEND, CMD_TXPOWER, radio.txpower, FEND],
            "configuring TX power",
        )?;
        self.write(
            &[FEND, CMD_SF, radio.sf, FEND],
            "configuring spreading factor",
        )?;
        self.write(&[FEND, CMD_CR, radio.cr, FEND], "configuring coding rate")?;
        self.write(
            &[FEND, CMD_RADIO_STATE, RADIO_STATE_ON, FEND],
            "configuring radio state",
        )
    }

    /// upstream `setNormalMode`.
    pub fn set_normal_mode(&mut self) -> std::io::Result<()> {
        self.write(
            &[FEND, CMD_CONF_DELETE, 0x00, FEND],
            "configuring device mode",
        )
    }

    /// upstream `setTNCMode`, which restarts an ESP32 board.
    pub fn set_tnc_mode(&mut self, platform: u8) -> std::io::Result<()> {
        self.write(
            &[FEND, CMD_CONF_SAVE, 0x00, FEND],
            "configuring device mode",
        )?;
        if platform == crate::rom::PLATFORM_ESP32 {
            self.hard_reset()?;
        }
        Ok(())
    }

    /// upstream `wipe_eeprom`, which waits for the device to finish.
    pub fn wipe_eeprom(&mut self, board: Option<u8>) -> std::io::Result<()> {
        self.write(&[FEND, CMD_ROM_WIPE, 0xf8, FEND], "wiping EEPROM")?;
        thread::sleep(Duration::from_secs(13));
        // The RAK4631's emulated EEPROM needs longer.
        if board == Some(crate::rom::BOARD_RAK4631) {
            thread::sleep(Duration::from_secs(10));
        }
        Ok(())
    }

    /// upstream `write_eeprom`: one byte at `addr`.
    pub fn write_eeprom(&mut self, addr: u8, byte: u8) -> std::io::Result<()> {
        self.write(&kiss::frame(CMD_ROM_WRITE, &[addr, byte]), "writing EEPROM")
    }

    /// upstream `store_signature`: the device signature.
    pub fn store_signature(&mut self, signature: &[u8]) -> std::io::Result<()> {
        self.write(
            &kiss::frame(CMD_DEV_SIG, signature),
            "sending signature to device",
        )
    }

    /// upstream `set_firmware_hash`.
    pub fn set_firmware_hash(&mut self, hash: &[u8]) -> std::io::Result<()> {
        self.write(
            &kiss::frame(CMD_FW_HASH, hash),
            "sending firmware hash to device",
        )
    }

    /// upstream `hard_reset`.
    pub fn hard_reset(&mut self) -> std::io::Result<()> {
        self.write(&[FEND, CMD_RESET, 0xf8, FEND], "restarting device")?;
        thread::sleep(Duration::from_secs(2));
        Ok(())
    }
}

/// The TNC radio parameters (`--freq`, `--bw`, `--txp`, `--sf`, `--cr`).
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct RadioConfig {
    pub frequency: u32,
    pub bandwidth: u32,
    pub txpower: u8,
    pub sf: u8,
    pub cr: u8,
}

/// Read frames from the device until the port closes, as upstream's
/// `readLoop` does. A frame is dropped when its bytes stop arriving for
/// upstream's 100 ms timeout.
fn read_loop(mut reader: std::fs::File, state: Arc<Mutex<Reported>>) {
    let mut in_frame = false;
    let mut escape = false;
    let mut command = CMD_UNKNOWN;
    let mut data_buffer: Vec<u8> = Vec::new();
    let mut command_buffer: Vec<u8> = Vec::new();
    let mut last_read = Instant::now();
    let mut buf = [0u8; 256];

    let unescape = |byte: u8, escape: &mut bool| -> Option<u8> {
        if byte == FESC {
            *escape = true;
            return None;
        }
        let mut byte = byte;
        if *escape {
            if byte == TFEND {
                byte = FEND;
            }
            if byte == TFESC {
                byte = FESC;
            }
            *escape = false;
        }
        Some(byte)
    };

    loop {
        let n = match reader.read(&mut buf) {
            Ok(0) | Err(_) => return,
            Ok(n) => n,
        };
        // upstream drops a partial frame after 100 ms without bytes.
        if !data_buffer.is_empty() && last_read.elapsed() > Duration::from_millis(100) {
            data_buffer.clear();
            in_frame = false;
            command = CMD_UNKNOWN;
            escape = false;
        }
        last_read = Instant::now();
        let mut state = state.lock().unwrap_or_else(|e| e.into_inner());
        for &byte in &buf[..n] {
            if in_frame && byte == FEND && command == CMD_ROM_READ {
                state.eeprom = Some(std::mem::take(&mut data_buffer));
                in_frame = false;
                command_buffer.clear();
            } else if in_frame && byte == FEND && command == CMD_CFG_READ {
                state.cfg_sector = Some(std::mem::take(&mut data_buffer));
                in_frame = false;
                command_buffer.clear();
            } else if byte == FEND {
                in_frame = true;
                command = CMD_UNKNOWN;
                data_buffer.clear();
                command_buffer.clear();
            } else if in_frame && data_buffer.len() < 1024 {
                if data_buffer.is_empty() && command == CMD_UNKNOWN {
                    command = byte;
                    continue;
                }
                match command {
                    CMD_ROM_READ | CMD_CFG_READ | CMD_DATA => {
                        if let Some(b) = unescape(byte, &mut escape) {
                            data_buffer.push(b);
                        }
                    }
                    CMD_FREQUENCY | CMD_BANDWIDTH | CMD_BT_PIN | CMD_STAT_RX | CMD_STAT_TX => {
                        if let Some(b) = unescape(byte, &mut escape) {
                            command_buffer.push(b);
                            if command_buffer.len() == 4 {
                                let v = u32::from_be_bytes([
                                    command_buffer[0],
                                    command_buffer[1],
                                    command_buffer[2],
                                    command_buffer[3],
                                ]);
                                match command {
                                    CMD_FREQUENCY => state.r_frequency = Some(v),
                                    CMD_BANDWIDTH => state.r_bandwidth = Some(v),
                                    CMD_BT_PIN => state.r_bt_pin = Some(v),
                                    _ => {}
                                }
                            }
                        }
                    }
                    CMD_DEV_HASH => {
                        if let Some(b) = unescape(byte, &mut escape) {
                            command_buffer.push(b);
                            if command_buffer.len() == 32 {
                                state.device_hash = Some(command_buffer.clone());
                            }
                        }
                    }
                    CMD_HASHES => {
                        if let Some(b) = unescape(byte, &mut escape) {
                            command_buffer.push(b);
                            if command_buffer.len() == 33 {
                                match command_buffer[0] {
                                    0x01 => {
                                        state.firmware_hash_target =
                                            Some(command_buffer[1..].to_vec())
                                    }
                                    0x02 => {
                                        state.firmware_hash = Some(command_buffer[1..].to_vec())
                                    }
                                    _ => {}
                                }
                            }
                        }
                    }
                    CMD_FW_VERSION => {
                        if let Some(b) = unescape(byte, &mut escape) {
                            command_buffer.push(b);
                            if command_buffer.len() == 2 {
                                state.major_version = Some(command_buffer[0]);
                                state.minor_version = Some(command_buffer[1]);
                            }
                        }
                    }
                    CMD_BOARD => state.board = Some(byte),
                    CMD_PLATFORM => state.platform = Some(byte),
                    CMD_MCU => state.mcu = Some(byte),
                    CMD_TXPOWER => state.r_txpower = Some(byte),
                    CMD_SF => state.r_sf = Some(byte),
                    CMD_CR => state.r_cr = Some(byte),
                    CMD_RADIO_STATE => state.r_state = Some(byte),
                    CMD_RADIO_LOCK => state.r_lock = Some(byte),
                    CMD_DETECT => state.detected = Some(byte == DETECT_RESP),
                    _ => {}
                }
            }
        }
    }
}
