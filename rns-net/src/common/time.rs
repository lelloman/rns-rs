//! Time utilities.

use std::cell::Cell;
use std::time::{SystemTime, UNIX_EPOCH};

std::thread_local! {
    /// The reading a [`hold`] scope took; [`OPEN`] in a scope that has not
    /// read the clock yet, 0 outside any scope.
    static HELD: Cell<f64> = const { Cell::new(0.0) };
}

/// [`HELD`] in a scope whose first [`now`] has not happened yet.
const OPEN: f64 = -1.0;

/// Returns the current time as seconds since the Unix epoch.
///
/// Inside a [`hold`] scope on this thread it returns the reading the scope
/// took, so the many steps that handle one event share one clock read.
pub fn now() -> f64 {
    HELD.with(|held| match held.get() {
        t if t > 0.0 => t,
        OPEN => {
            let t = read();
            held.set(t);
            t
        }
        _ => read(),
    })
}

fn read() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs_f64()
}

/// Have [`now`] on this thread read the clock at most once until the
/// returned guard drops: the first call in the scope reads it, and later
/// calls return that reading. A nested scope keeps the outer reading.
///
/// Hold it only around work that finishes promptly, such as handling one
/// driver event: code inside sees time stand still, so a loop waiting on
/// [`now`] to advance would never end.
pub(crate) fn hold() -> Held {
    let outer = HELD.with(Cell::get);
    if outer == 0.0 {
        HELD.with(|held| held.set(OPEN));
    }
    Held { outer }
}

/// Guard of a [`hold`] scope; dropping it restores the enclosing scope.
pub(crate) struct Held {
    outer: f64,
}

impl Drop for Held {
    fn drop(&mut self) {
        HELD.with(|held| held.set(self.outer));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn now_returns_reasonable_epoch() {
        let t = now();
        // Should be after 2024-01-01 (1704067200)
        assert!(t > 1_704_067_200.0);
        // Should be before 2050-01-01 (2524608000)
        assert!(t < 2_524_608_000.0);
    }

    #[test]
    fn now_is_monotonic() {
        let t1 = now();
        let t2 = now();
        assert!(t2 >= t1);
    }

    #[test]
    fn a_hold_scope_returns_one_reading_and_releases_it() {
        let outer = hold();
        let held = now();
        std::thread::sleep(std::time::Duration::from_millis(2));
        assert_eq!(now(), held);
        {
            let _inner = hold();
            assert_eq!(now(), held, "a nested scope keeps the outer reading");
        }
        assert_eq!(now(), held);
        drop(outer);
        assert!(now() > held, "the clock runs again once the scope ends");
    }

    #[test]
    fn a_hold_scope_reads_the_clock_at_its_first_now() {
        let _held = hold();
        std::thread::sleep(std::time::Duration::from_millis(2));
        let before = read();
        let first = now();
        assert!(first >= before, "the scope read the clock when first asked");
        assert_eq!(now(), first);
    }

    #[test]
    fn a_hold_scope_is_per_thread() {
        let _held = hold();
        let t = now();
        std::thread::sleep(std::time::Duration::from_millis(2));
        let other = std::thread::spawn(now).join().unwrap();
        assert!(other > t);
    }
}
