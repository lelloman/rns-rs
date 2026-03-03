//! SSD1306 OLED display driver for Heltec V3.
//!
//! Shows identity hash, TX/RX counters, and status on the 128x64 OLED.
//! Supports multiple pages cycled by long-pressing the PRG button.

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

const NUM_PAGES: u8 = 3;

/// Shared display stats updated by the driver.
pub struct DisplayStats {
    pub identity_hex: String,
    pub tx_bytes: u32,
    pub rx_bytes: u32,
    pub announces: u32,
    pub page: u8,
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
            status: None,
            status_ttl: 0,
        }
    }

    pub fn cycle_page(&mut self) {
        self.page = (self.page + 1) % NUM_PAGES;
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
    rst.set_high().ok();
    std::thread::sleep(std::time::Duration::from_millis(1));
    rst.set_low().ok();
    std::thread::sleep(std::time::Duration::from_millis(10));
    rst.set_high().ok();
    std::thread::sleep(std::time::Duration::from_millis(20));

    // Keep RST pin alive — dropping it would float the line and reset the display
    std::mem::forget(rst);

    // Scan I2C bus to verify display is present
    for addr in [0x3Cu8, 0x3D] {
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
fn render_radio_info(display: &mut Display, _stats: &DisplayStats) {
    let style = MonoTextStyleBuilder::new()
        .font(&FONT_6X10)
        .text_color(BinaryColor::On)
        .build();

    let _ = Text::new("Radio Info", Point::new(0, 10), style).draw(display);

    let freq = format!("Freq: {} MHz", crate::config::LORA_FREQUENCY / 1_000_000);
    let _ = Text::new(&freq, Point::new(0, 24), style).draw(display);

    let params = format!(
        "SF:{} BW:{}k CR:4/{}",
        crate::config::LORA_SPREADING_FACTOR,
        crate::config::LORA_BANDWIDTH / 1000,
        crate::config::LORA_CODING_RATE,
    );
    let _ = Text::new(&params, Point::new(0, 38), style).draw(display);

    let power = format!("TX Power: {} dBm", crate::config::LORA_TX_POWER);
    let _ = Text::new(&power, Point::new(0, 52), style).draw(display);

    let _ = Text::new(&format!("[2/{}]", NUM_PAGES), Point::new(104, 62), style).draw(display);
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

    let _ = Text::new(&format!("[3/{}]", NUM_PAGES), Point::new(104, 62), style).draw(display);
}

/// Render the current page.
fn render(display: &mut Display, stats: &DisplayStats) {
    display.clear_buffer();

    match stats.page {
        0 => render_stats(display, stats),
        1 => render_radio_info(display, stats),
        2 => render_identity(display, stats),
        _ => render_stats(display, stats),
    }

    let _ = display.flush();
}

/// Display refresh loop. Run in a dedicated thread.
pub fn refresh_loop(mut display: Display, stats: SharedStats) {
    loop {
        {
            let mut s = stats.lock().unwrap();
            render(&mut display, &s);
            s.tick_status();
        }
        std::thread::sleep(std::time::Duration::from_millis(500));
    }
}
