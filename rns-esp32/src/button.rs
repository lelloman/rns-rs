//! GPIO0 (PRG) button handler with debounce and gesture detection.
//!
//! Detects four gestures:
//! - Short press → cycle display page
//! - Long press (>800ms) → trigger announce (node mode only)
//! - Double press (<400ms gap) → send ping
//! - Triple press (<400ms gaps) → enable BLE bridge mode

use std::sync::mpsc;
use std::time::{Duration, Instant};

use esp_idf_hal::gpio::{AnyIOPin, Input, PinDriver};

use crate::display::SharedStats;
use crate::driver::Event;

const DEBOUNCE_MS: u64 = 50;
const LONG_PRESS_MS: u64 = 800;
const MULTI_PRESS_WINDOW_MS: u64 = 400;

/// Run the button polling loop. Blocks forever. Call from a dedicated thread.
///
/// Short press cycles the display page directly via shared stats.
/// Long press, double press, and triple press send events to the driver channel.
pub fn button_loop(
    pin: PinDriver<'static, AnyIOPin, Input>,
    tx: mpsc::Sender<Event>,
    stats: SharedStats,
) {
    let mut press_start: Option<Instant> = None;
    let mut was_low = false;
    // Track consecutive short presses for multi-press gestures
    let mut short_press_count: u8 = 0;
    let mut last_short_press: Option<Instant> = None;

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
                    short_press_count = 0;
                    last_short_press = None;
                } else if held >= Duration::from_millis(DEBOUNCE_MS) {
                    // Short press — accumulate for multi-press detection
                    let in_window = last_short_press
                        .map(|t| t.elapsed() < Duration::from_millis(MULTI_PRESS_WINDOW_MS))
                        .unwrap_or(false);

                    if in_window {
                        short_press_count += 1;
                    } else {
                        // Previous pending presses expired — commit them first
                        commit_pending_presses(short_press_count, &tx, &stats);
                        short_press_count = 1;
                    }
                    last_short_press = Some(Instant::now());
                }
            }
        }

        // Commit pending presses if multi-press window expired
        if short_press_count > 0 {
            if let Some(prev) = last_short_press {
                if prev.elapsed() >= Duration::from_millis(MULTI_PRESS_WINDOW_MS) {
                    commit_pending_presses(short_press_count, &tx, &stats);
                    short_press_count = 0;
                    last_short_press = None;
                }
            }
        }

        was_low = is_pressed;
        std::thread::sleep(Duration::from_millis(10));
    }
}

/// Commit accumulated short presses as the appropriate gesture.
fn commit_pending_presses(count: u8, tx: &mpsc::Sender<Event>, stats: &SharedStats) {
    match count {
        0 => {}
        1 => {
            // Single press → cycle display page
            stats.lock().unwrap().cycle_page();
        }
        2 => {
            // Double press → send ping
            let _ = tx.send(Event::SendPing);
        }
        _ => {
            // Triple (or more) press → enable BLE
            let _ = tx.send(Event::EnableBle);
        }
    }
}
