//! SSD1306 OLED display driver for Heltec V3.
//!
//! Mode-aware display with separate page sets for standalone and bridge modes.
//! Pages are cycled by short-pressing the PRG button (includes an "off" page).

use std::sync::{Arc, Mutex};

use embedded_graphics::mono_font::ascii::FONT_6X10;
use embedded_graphics::mono_font::MonoTextStyleBuilder;
use embedded_graphics::pixelcolor::BinaryColor;
use embedded_graphics::prelude::*;
use embedded_graphics::text::Text;

use esp_idf_hal::gpio::{AnyIOPin, Output, PinDriver};
use esp_idf_hal::i2c::I2cDriver;

use ssd1306::mode::BufferedGraphicsMode;
use ssd1306::prelude::*;
use ssd1306::rotation::DisplayRotation;
use ssd1306::size::DisplaySize128x64;
use ssd1306::I2CDisplayInterface;
use ssd1306::Ssd1306;

type Display = Ssd1306<
    ssd1306::prelude::I2CInterface<I2cDriver<'static>>,
    DisplaySize128x64,
    BufferedGraphicsMode<DisplaySize128x64>,
>;

const STANDALONE_NUM_PAGES: u8 = 4; // stats, radio, identity, off
const BRIDGE_NUM_PAGES: u8 = 3; // bridge status, bridge radio, off
const BLE_WAITING_NUM_PAGES: u8 = 2; // ble status, off

#[derive(Clone, Copy, PartialEq)]
pub enum Mode {
    Standalone,
    Bridge,
    BleWaiting,
}

/// Shared display stats updated by the driver.
pub struct DisplayStats {
    pub identity_hex: String,
    pub tx_bytes: u32,
    pub rx_bytes: u32,
    pub announces: u32,
    pub page: u8,
    pub mode: Mode,
    // Bridge-mode stats
    pub bridge_tx_bytes: u32,
    pub bridge_rx_bytes: u32,
    pub bridge_freq: Option<u32>,
    pub bridge_bw: Option<u32>,
    pub bridge_sf: Option<u8>,
    pub bridge_cr: Option<u8>,
    pub bridge_power: Option<i8>,
    pub active_freq: u32,
    pub active_bw: u32,
    pub active_sf: u8,
    pub active_cr: u8,
    pub active_power: i8,
    /// Temporary status message (shown for a few refresh cycles then cleared).
    status: Option<String>,
    status_ttl: u8,
}

impl DisplayStats {
    pub fn new(identity_hex: String) -> Self {
        Self {
            identity_hex,
            tx_bytes: 0,
            rx_bytes: 0,
            announces: 0,
            page: 0,
            mode: Mode::Standalone,
            bridge_tx_bytes: 0,
            bridge_rx_bytes: 0,
            bridge_freq: None,
            bridge_bw: None,
            bridge_sf: None,
            bridge_cr: None,
            bridge_power: None,
            active_freq: crate::config::LORA_FREQUENCY,
            active_bw: crate::config::LORA_BANDWIDTH,
            active_sf: crate::config::LORA_SPREADING_FACTOR,
            active_cr: crate::config::LORA_CODING_RATE,
            active_power: crate::config::LORA_TX_POWER,
            status: None,
            status_ttl: 0,
        }
    }

    fn num_pages(&self) -> u8 {
        match self.mode {
            Mode::Standalone => STANDALONE_NUM_PAGES,
            Mode::Bridge => BRIDGE_NUM_PAGES,
            Mode::BleWaiting => BLE_WAITING_NUM_PAGES,
        }
    }

    pub fn cycle_page(&mut self) {
        self.page = (self.page + 1) % self.num_pages();
    }

    pub fn set_mode(&mut self, mode: Mode) {
        self.mode = mode;
        self.page = 0;
        if mode == Mode::Bridge {
            self.bridge_tx_bytes = 0;
            self.bridge_rx_bytes = 0;
            self.bridge_freq = None;
            self.bridge_bw = None;
            self.bridge_sf = None;
            self.bridge_cr = None;
            self.bridge_power = None;
        }
    }

    fn is_off_page(&self) -> bool {
        self.page == self.num_pages() - 1
    }

    pub fn set_status(&mut self, msg: &str) {
        self.status = Some(String::from(msg));
        self.status_ttl = 6; // ~3 seconds at 500ms refresh
    }

    fn tick_status(&mut self) {
        if self.status_ttl > 0 {
            self.status_ttl -= 1;
            if self.status_ttl == 0 {
                self.status = None;
            }
        }
    }
}

pub type SharedStats = Arc<Mutex<DisplayStats>>;

/// Initialize the OLED display.
pub fn init(
    mut i2c: I2cDriver<'static>,
    mut rst: PinDriver<'static, AnyIOPin, Output>,
) -> Option<Display> {
    // Reset the display — hold low, then release
    if let Err(e) = rst.set_high() {
        log::warn!("OLED RST set_high failed: {:?}", e);
    }
    std::thread::sleep(std::time::Duration::from_millis(1));
    if let Err(e) = rst.set_low() {
        log::warn!("OLED RST set_low failed: {:?}", e);
    }
    std::thread::sleep(std::time::Duration::from_millis(10));
    if let Err(e) = rst.set_high() {
        log::warn!("OLED RST release failed: {:?}", e);
    }
    std::thread::sleep(std::time::Duration::from_millis(20));

    // Keep RST pin alive — dropping it would float the line and reset the display
    std::mem::forget(rst);

    // Scan I2C bus to verify display is present
    for addr in [crate::config::OLED_ADDR, 0x3D] {
        let probe: Result<(), _> = i2c.write(addr, &[0x00], 100);
        match probe {
            Ok(()) => log::info!("I2C device found at 0x{:02X}", addr),
            Err(e) => log::warn!("I2C no response at 0x{:02X}: {:?}", addr, e),
        }
    }

    let interface = I2CDisplayInterface::new(i2c);
    let mut display = Ssd1306::new(interface, DisplaySize128x64, DisplayRotation::Rotate0)
        .into_buffered_graphics_mode();

    match display.init() {
        Ok(()) => {
            let _ = display.set_display_on(true);
            let _ = display.set_brightness(Brightness::BRIGHTEST);
            display.clear_buffer();
            let _ = display.flush();
            log::info!("OLED display initialized and cleared");
            Some(display)
        }
        Err(e) => {
            log::error!("OLED init failed: {:?}", e);
            None
        }
    }
}

/// Render page 0: main stats.
fn render_stats(display: &mut Display, stats: &DisplayStats) {
    let style = MonoTextStyleBuilder::new()
        .font(&FONT_6X10)
        .text_color(BinaryColor::On)
        .build();

    let _ = Text::new("RNS LoRa Node", Point::new(0, 10), style).draw(display);

    let id_short = if stats.identity_hex.len() >= 16 {
        &stats.identity_hex[..16]
    } else {
        &stats.identity_hex
    };
    let _ = Text::new(id_short, Point::new(0, 24), style).draw(display);

    let counter_line = format!("TX:{}B RX:{}B", stats.tx_bytes, stats.rx_bytes);
    let _ = Text::new(&counter_line, Point::new(0, 40), style).draw(display);

    // Line 4: status message or announce count
    if let Some(ref msg) = stats.status {
        let _ = Text::new(msg, Point::new(0, 54), style).draw(display);
    } else {
        let ann_line = format!("Announces:{}", stats.announces);
        let _ = Text::new(&ann_line, Point::new(0, 54), style).draw(display);
    }
}

/// Render page 1: radio info.
fn render_radio_info(display: &mut Display, stats: &DisplayStats) {
    let style = MonoTextStyleBuilder::new()
        .font(&FONT_6X10)
        .text_color(BinaryColor::On)
        .build();

    let _ = Text::new("Radio Info", Point::new(0, 10), style).draw(display);

    let freq = format!("Freq: {} MHz", stats.active_freq / 1_000_000);
    let _ = Text::new(&freq, Point::new(0, 24), style).draw(display);

    let params = format!(
        "SF:{} BW:{}k CR:4/{}",
        stats.active_sf,
        stats.active_bw / 1000,
        stats.active_cr,
    );
    let _ = Text::new(&params, Point::new(0, 38), style).draw(display);

    let power = format!("TX Power: {} dBm", stats.active_power);
    let _ = Text::new(&power, Point::new(0, 52), style).draw(display);

    let _ = Text::new(
        &format!("[2/{}]", STANDALONE_NUM_PAGES),
        Point::new(104, 62),
        style,
    )
    .draw(display);
}

/// Render page 2: full identity hash.
fn render_identity(display: &mut Display, stats: &DisplayStats) {
    let style = MonoTextStyleBuilder::new()
        .font(&FONT_6X10)
        .text_color(BinaryColor::On)
        .build();

    let _ = Text::new("Identity Hash", Point::new(0, 10), style).draw(display);

    // Split identity hex into rows of 21 chars (fits 128px / 6px per char)
    let hex = &stats.identity_hex;
    let row_len = 21;
    for (i, chunk_start) in (0..hex.len()).step_by(row_len).enumerate() {
        let chunk_end = (chunk_start + row_len).min(hex.len());
        let line = &hex[chunk_start..chunk_end];
        let y = 24 + (i as i32) * 14;
        let _ = Text::new(line, Point::new(0, y), style).draw(display);
    }

    let _ = Text::new(
        &format!("[3/{}]", STANDALONE_NUM_PAGES),
        Point::new(104, 62),
        style,
    )
    .draw(display);
}

/// Render page: bridge status.
fn render_bridge_status(display: &mut Display, stats: &DisplayStats) {
    let style = MonoTextStyleBuilder::new()
        .font(&FONT_6X10)
        .text_color(BinaryColor::On)
        .build();

    let _ = Text::new("RNode Bridge", Point::new(0, 10), style).draw(display);

    let counter_line = format!(
        "TX:{}B RX:{}B",
        stats.bridge_tx_bytes, stats.bridge_rx_bytes
    );
    let _ = Text::new(&counter_line, Point::new(0, 24), style).draw(display);

    if let Some(ref msg) = stats.status {
        let _ = Text::new(msg, Point::new(0, 40), style).draw(display);
    }

    let _ = Text::new(
        &format!("[1/{}]", stats.num_pages()),
        Point::new(104, 62),
        style,
    )
    .draw(display);
}

/// Render page: bridge radio config (as received from host).
fn render_bridge_radio(display: &mut Display, stats: &DisplayStats) {
    let style = MonoTextStyleBuilder::new()
        .font(&FONT_6X10)
        .text_color(BinaryColor::On)
        .build();

    let _ = Text::new("Bridge Radio", Point::new(0, 10), style).draw(display);

    let freq = stats.bridge_freq.unwrap_or(crate::config::LORA_FREQUENCY);
    let _ = Text::new(
        &format!("Freq: {} MHz", freq / 1_000_000),
        Point::new(0, 24),
        style,
    )
    .draw(display);

    let sf = stats
        .bridge_sf
        .unwrap_or(crate::config::LORA_SPREADING_FACTOR);
    let bw = stats.bridge_bw.unwrap_or(crate::config::LORA_BANDWIDTH);
    let cr = stats.bridge_cr.unwrap_or(crate::config::LORA_CODING_RATE);
    let _ = Text::new(
        &format!("SF:{} BW:{}k CR:4/{}", sf, bw / 1000, cr),
        Point::new(0, 38),
        style,
    )
    .draw(display);

    let power = stats.bridge_power.unwrap_or(crate::config::LORA_TX_POWER);
    let _ = Text::new(
        &format!("TX Power: {} dBm", power),
        Point::new(0, 52),
        style,
    )
    .draw(display);

    let _ = Text::new(
        &format!("[2/{}]", stats.num_pages()),
        Point::new(104, 62),
        style,
    )
    .draw(display);
}

/// Render page: BLE waiting / advertising status.
fn render_ble_waiting(display: &mut Display, stats: &DisplayStats) {
    let style = MonoTextStyleBuilder::new()
        .font(&FONT_6X10)
        .text_color(BinaryColor::On)
        .build();

    let _ = Text::new("BLE Bridge", Point::new(0, 10), style).draw(display);
    let _ = Text::new("Waiting for", Point::new(0, 28), style).draw(display);
    let _ = Text::new("connection...", Point::new(0, 42), style).draw(display);

    if let Some(ref msg) = stats.status {
        let _ = Text::new(msg, Point::new(0, 56), style).draw(display);
    }
}

/// Render the current page. Returns whether the display should be on.
fn render(display: &mut Display, stats: &DisplayStats) -> bool {
    if stats.is_off_page() {
        display.clear_buffer();
        let _ = display.flush();
        return false;
    }

    display.clear_buffer();

    match stats.mode {
        Mode::Standalone => match stats.page {
            0 => render_stats(display, stats),
            1 => render_radio_info(display, stats),
            2 => render_identity(display, stats),
            _ => render_stats(display, stats),
        },
        Mode::Bridge => match stats.page {
            0 => render_bridge_status(display, stats),
            1 => render_bridge_radio(display, stats),
            _ => render_bridge_status(display, stats),
        },
        Mode::BleWaiting => match stats.page {
            0 => render_ble_waiting(display, stats),
            _ => render_ble_waiting(display, stats),
        },
    }

    let _ = display.flush();
    true
}

/// Display refresh loop. Run in a dedicated thread.
pub fn refresh_loop(mut display: Display, stats: SharedStats) {
    let mut display_on = true;

    loop {
        {
            let mut s = stats.lock().unwrap();
            let should_be_on = render(&mut display, &s);
            s.tick_status();

            if should_be_on != display_on {
                let _ = display.set_display_on(should_be_on);
                display_on = should_be_on;
            }
        }
        std::thread::sleep(std::time::Duration::from_millis(500));
    }
}
