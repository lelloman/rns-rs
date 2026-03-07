//! GPIO0 (PRG) button handler with debounce and gesture detection.
//!
//! Detects three gestures:
//! - Short press → cycle display page
//! - Long press (>800ms) → trigger announce (node mode only)
//! - Double press (<400ms gap) → send ping

use std::sync::mpsc;
use std::time::{Duration, Instant};

use esp_idf_hal::gpio::{AnyIOPin, Input, PinDriver};

use crate::display::SharedStats;
use crate::driver::Event;

const DEBOUNCE_MS: u64 = 50;
const LONG_PRESS_MS: u64 = 800;
const DOUBLE_PRESS_WINDOW_MS: u64 = 400;

/// Run the button polling loop. Blocks forever. Call from a dedicated thread.
///
/// Short press cycles the display page directly via shared stats.
/// Long press and double press send events to the driver channel.
pub fn button_loop(
    pin: PinDriver<'static, AnyIOPin, Input>,
    tx: mpsc::Sender<Event>,
    stats: SharedStats,
) {
    let mut last_press: Option<Instant> = None;
    let mut press_start: Option<Instant> = None;
    let mut was_low = false;
    let mut pending_short = false;

    loop {
        let is_pressed = pin.is_low(); // PRG button is active-low

        if is_pressed && !was_low {
            // Button just pressed (falling edge)
            press_start = Some(Instant::now());
        } else if !is_pressed && was_low {
            // Button just released (rising edge)
            if let Some(start) = press_start.take() {
                let held = start.elapsed();

                if held >= Duration::from_millis(LONG_PRESS_MS) {
                    // Long press → trigger announce
                    let _ = tx.send(Event::SendAnnounce);
                    pending_short = false;
                } else if held >= Duration::from_millis(DEBOUNCE_MS) {
                    // Short press candidate — check for double press
                    if let Some(prev) = last_press {
                        if prev.elapsed() < Duration::from_millis(DOUBLE_PRESS_WINDOW_MS) {
                            // Double press → send ping
                            let _ = tx.send(Event::SendPing);
                            pending_short = false;
                            last_press = None;
                        } else {
                            // Too slow for double, commit previous pending short
                            if pending_short {
                                stats.lock().unwrap().cycle_page();
                            }
                            pending_short = true;
                            last_press = Some(Instant::now());
                        }
                    } else {
                        pending_short = true;
                        last_press = Some(Instant::now());
                    }
                }
            }
        }

        // Commit pending short press if double-press window expired
        if pending_short {
            if let Some(prev) = last_press {
                if prev.elapsed() >= Duration::from_millis(DOUBLE_PRESS_WINDOW_MS) {
                    stats.lock().unwrap().cycle_page();
                    pending_short = false;
                    last_press = None;
                }
            }
        }

        was_low = is_pressed;
        std::thread::sleep(Duration::from_millis(10));
    }
}
