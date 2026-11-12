//! A fake RNode on a pseudo-terminal: it answers the firmware commands
//! `rnodeconf` sends and records every frame it receives, so a test can run
//! the real `rnodeconf` (ours, or upstream's Python one) against it.

use std::io::{Read, Write};
use std::os::unix::io::FromRawFd;
use std::sync::{Arc, Mutex};
use std::thread;

pub const FEND: u8 = 0xC0;
pub const FESC: u8 = 0xDB;
pub const TFEND: u8 = 0xDC;
pub const TFESC: u8 = 0xDD;

pub const CMD_FREQUENCY: u8 = 0x01;
pub const CMD_BANDWIDTH: u8 = 0x02;
pub const CMD_TXPOWER: u8 = 0x03;
pub const CMD_SF: u8 = 0x04;
pub const CMD_CR: u8 = 0x05;
pub const CMD_RADIO_STATE: u8 = 0x06;
pub const CMD_DETECT: u8 = 0x08;
pub const CMD_LEAVE: u8 = 0x0A;
pub const CMD_DISP_INT: u8 = 0x45;
pub const CMD_BT_CTRL: u8 = 0x46;
pub const CMD_DISP_ADR: u8 = 0x63;
pub const CMD_DISP_BLNK: u8 = 0x64;
pub const CMD_NP_INT: u8 = 0x65;
pub const CMD_DISP_ROT: u8 = 0x67;
pub const CMD_DISP_RCND: u8 = 0x68;
pub const CMD_DIS_IA: u8 = 0x69;
pub const CMD_WIFI_MODE: u8 = 0x6A;
pub const CMD_WIFI_SSID: u8 = 0x6B;
pub const CMD_WIFI_PSK: u8 = 0x6C;
pub const CMD_WIFI_CHN: u8 = 0x6E;
pub const CMD_WIFI_IP: u8 = 0x84;
pub const CMD_WIFI_NM: u8 = 0x85;
pub const CMD_BOARD: u8 = 0x47;
pub const CMD_PLATFORM: u8 = 0x48;
pub const CMD_MCU: u8 = 0x49;
pub const CMD_FW_VERSION: u8 = 0x50;
pub const CMD_ROM_READ: u8 = 0x51;
pub const CMD_ROM_WRITE: u8 = 0x52;
pub const CMD_CONF_SAVE: u8 = 0x53;
pub const CMD_CONF_DELETE: u8 = 0x54;
pub const CMD_RESET: u8 = 0x55;
pub const CMD_DEV_HASH: u8 = 0x56;
pub const CMD_DEV_SIG: u8 = 0x57;
pub const CMD_FW_HASH: u8 = 0x58;
pub const CMD_ROM_WIPE: u8 = 0x59;
pub const CMD_HASHES: u8 = 0x60;
pub const CMD_FW_UPD: u8 = 0x61;
pub const CMD_CFG_READ: u8 = 0x6D;

/// What the fake device reports.
#[derive(Clone)]
pub struct Device {
    pub eeprom: Vec<u8>,
    pub cfg_sector: Vec<u8>,
    pub version: (u8, u8),
    pub platform: u8,
    pub mcu: u8,
    pub board: u8,
}

/// A running fake RNode.
pub struct FakeRNode {
    pub path: String,
    /// The frames received, unescaped, each as `[command, payload...]`.
    pub frames: Arc<Mutex<Vec<Vec<u8>>>>,
    /// The device's state, which EEPROM writes and wipes change.
    pub device: Arc<Mutex<Device>>,
    _slave: std::fs::File,
}

impl FakeRNode {
    pub fn start(device: Device) -> Self {
        let mut master: libc::c_int = -1;
        let mut slave: libc::c_int = -1;
        // SAFETY: openpty fills in the two descriptors.
        let ret = unsafe {
            libc::openpty(
                &mut master,
                &mut slave,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )
        };
        assert_eq!(ret, 0, "openpty failed");
        for fd in [master, slave] {
            // SAFETY: plain termios calls on descriptors we own.
            unsafe {
                let mut termios: libc::termios = std::mem::zeroed();
                libc::tcgetattr(fd, &mut termios);
                libc::cfmakeraw(&mut termios);
                libc::tcsetattr(fd, libc::TCSANOW, &termios);
            }
        }
        // SAFETY: ttyname_r writes the slave's path into the buffer.
        let path = unsafe {
            let mut buf = [0 as libc::c_char; 128];
            assert_eq!(libc::ttyname_r(slave, buf.as_mut_ptr(), buf.len()), 0);
            std::ffi::CStr::from_ptr(buf.as_ptr())
                .to_string_lossy()
                .into_owned()
        };
        // SAFETY: we own both descriptors; the slave stays open so the
        // master does not see a hangup between clients.
        let master = unsafe { std::fs::File::from_raw_fd(master) };
        let slave = unsafe { std::fs::File::from_raw_fd(slave) };
        let frames = Arc::new(Mutex::new(Vec::new()));
        let recorded = Arc::clone(&frames);
        let device = Arc::new(Mutex::new(device));
        let state = Arc::clone(&device);
        thread::spawn(move || serve(master, state, recorded));
        Self {
            path,
            frames,
            device,
            _slave: slave,
        }
    }

    /// The frames received once the device has gone quiet: a tool can
    /// exit right after writing its last frame, before this side has read
    /// it from the pseudo-terminal.
    pub fn received(&self) -> Vec<Vec<u8>> {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        let mut last = self.frames.lock().unwrap().len();
        loop {
            thread::sleep(std::time::Duration::from_millis(300));
            let now = self.frames.lock().unwrap().len();
            if now == last || std::time::Instant::now() >= deadline {
                return self.frames.lock().unwrap().clone();
            }
            last = now;
        }
    }
}

fn escape(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    for &b in data {
        match b {
            FESC => out.extend_from_slice(&[FESC, TFESC]),
            FEND => out.extend_from_slice(&[FESC, TFEND]),
            _ => out.push(b),
        }
    }
    out
}

fn reply(command: u8, payload: &[u8]) -> Vec<u8> {
    let mut out = vec![FEND, command];
    out.extend(escape(payload));
    out.push(FEND);
    out
}

fn serve(mut master: std::fs::File, device: Arc<Mutex<Device>>, frames: Arc<Mutex<Vec<Vec<u8>>>>) {
    let mut writer = master.try_clone().expect("clone master");
    let mut buf = [0u8; 512];
    let mut frame: Vec<u8> = Vec::new();
    let mut in_frame = false;
    let mut escape = false;
    loop {
        let n = match master.read(&mut buf) {
            Ok(0) => continue,
            Ok(n) => n,
            // EIO while no client has the slave open.
            Err(_) => {
                thread::sleep(std::time::Duration::from_millis(20));
                continue;
            }
        };
        for &byte in &buf[..n] {
            if byte == FEND {
                if in_frame && !frame.is_empty() {
                    let done = std::mem::take(&mut frame);
                    let response = respond(&mut device.lock().unwrap(), &done);
                    frames.lock().unwrap().push(done);
                    if !response.is_empty() {
                        let _ = writer.write_all(&response);
                    }
                }
                in_frame = true;
                escape = false;
                continue;
            }
            if !in_frame {
                continue;
            }
            if byte == FESC {
                escape = true;
                continue;
            }
            let byte = match (escape, byte) {
                (true, TFEND) => FEND,
                (true, TFESC) => FESC,
                (_, b) => b,
            };
            escape = false;
            frame.push(byte);
        }
    }
}

fn respond(device: &mut Device, frame: &[u8]) -> Vec<u8> {
    let (&command, payload) = frame.split_first().unwrap();
    match command {
        CMD_DETECT => reply(CMD_DETECT, &[0x46]),
        CMD_FW_VERSION => reply(CMD_FW_VERSION, &[device.version.0, device.version.1]),
        CMD_PLATFORM => reply(CMD_PLATFORM, &[device.platform]),
        CMD_MCU => reply(CMD_MCU, &[device.mcu]),
        CMD_BOARD => reply(CMD_BOARD, &[device.board]),
        CMD_DEV_HASH => reply(CMD_DEV_HASH, &[0x11; 32]),
        CMD_HASHES => {
            // The target firmware hash (type 1) is all 0x22, the actual
            // one (type 2) all 0x33.
            let kind = payload.first().copied().unwrap_or(1);
            let mut hash = vec![kind];
            hash.extend_from_slice(&[if kind == 2 { 0x33 } else { 0x22 }; 32]);
            reply(CMD_HASHES, &hash)
        }
        CMD_ROM_READ => reply(CMD_ROM_READ, &device.eeprom),
        CMD_CFG_READ => reply(CMD_CFG_READ, &device.cfg_sector),
        CMD_ROM_WRITE => {
            if let [addr, byte] = payload {
                if let Some(slot) = device.eeprom.get_mut(*addr as usize) {
                    *slot = *byte;
                }
            }
            Vec::new()
        }
        CMD_ROM_WIPE => {
            device.eeprom.iter_mut().for_each(|b| *b = 0xFF);
            Vec::new()
        }
        _ => Vec::new(),
    }
}

/// A provisioned EEPROM image.
pub fn eeprom(
    product: u8,
    model: u8,
    hw_rev: u8,
    serialno: [u8; 4],
    made: u32,
    tnc: Option<(u8, u8, u8, u32, u32)>,
) -> Vec<u8> {
    let mut e = vec![0xFFu8; 296];
    e[0x00] = product;
    e[0x01] = model;
    e[0x02] = hw_rev;
    e[0x03..0x07].copy_from_slice(&serialno);
    e[0x07..0x0B].copy_from_slice(&made.to_be_bytes());
    let mut summed = vec![product, model, hw_rev];
    summed.extend_from_slice(&serialno);
    summed.extend_from_slice(&made.to_be_bytes());
    e[0x0B..0x1B].copy_from_slice(&rns_net::md5::md5(&summed));
    e[0x9B] = 0x73;
    if let Some((sf, cr, txp, freq, bw)) = tnc {
        e[0x9C] = sf;
        e[0x9D] = cr;
        e[0x9E] = txp;
        e[0x9F..0xA3].copy_from_slice(&bw.to_be_bytes());
        e[0xA3..0xA7].copy_from_slice(&freq.to_be_bytes());
        e[0xA7] = 0x73;
    }
    e
}
