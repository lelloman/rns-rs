//! Logical Rust allocation accounting; native malloc and allocator overhead excluded.
use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicU64, Ordering::Relaxed};

#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize)]
pub struct Snapshot {
    pub allocation_calls: u64,
    pub reallocation_calls: u64,
    pub allocated_bytes: u64,
    pub freed_bytes: u64,
    pub live_bytes: u64,
    pub peak_live_bytes: u64,
}

pub struct Counters {
    allocations: AtomicU64,
    reallocations: AtomicU64,
    allocated: AtomicU64,
    freed: AtomicU64,
    live: AtomicU64,
    peak: AtomicU64,
}
impl Counters {
    pub const fn new() -> Self {
        Self {
            allocations: AtomicU64::new(0),
            reallocations: AtomicU64::new(0),
            allocated: AtomicU64::new(0),
            freed: AtomicU64::new(0),
            live: AtomicU64::new(0),
            peak: AtomicU64::new(0),
        }
    }
    fn allocate(&self, bytes: u64) {
        self.allocations.fetch_add(1, Relaxed);
        self.allocated.fetch_add(bytes, Relaxed);
        self.grow(bytes);
    }
    fn grow(&self, bytes: u64) {
        let live = self.live.fetch_add(bytes, Relaxed) + bytes;
        self.peak.fetch_max(live, Relaxed);
    }
    fn deallocate(&self, bytes: u64) {
        self.freed.fetch_add(bytes, Relaxed);
        self.live.fetch_sub(bytes, Relaxed);
    }
    fn reallocate(&self, old: u64, new: u64) {
        self.reallocations.fetch_add(1, Relaxed);
        self.allocated.fetch_add(new, Relaxed);
        self.freed.fetch_add(old, Relaxed);
        // Logical live size; do not invent overlap for an in-place realloc.
        if new >= old {
            self.grow(new - old);
        } else {
            self.live.fetch_sub(old - new, Relaxed);
        }
    }
    pub fn reset_peak(&self) {
        self.peak.store(self.live.load(Relaxed), Relaxed);
    }
    pub fn snapshot(&self) -> Snapshot {
        Snapshot {
            allocation_calls: self.allocations.load(Relaxed),
            reallocation_calls: self.reallocations.load(Relaxed),
            allocated_bytes: self.allocated.load(Relaxed),
            freed_bytes: self.freed.load(Relaxed),
            live_bytes: self.live.load(Relaxed),
            peak_live_bytes: self.peak.load(Relaxed),
        }
    }
}

#[cfg(feature = "allocation-profiler")]
pub static COUNTERS: Counters = Counters::new();

#[cfg(feature = "allocation-profiler")]
mod allocator {
    use super::COUNTERS;
    use std::alloc::{GlobalAlloc, Layout, System};
    pub struct Tracked;
    // Safety: requests are forwarded unchanged to System, using its original
    // pointer and layout. Accounting uses only atomics and never allocates.
    unsafe impl GlobalAlloc for Tracked {
        unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
            let ptr = unsafe { System.alloc(layout) };
            if !ptr.is_null() {
                COUNTERS.allocate(layout.size() as u64);
            }
            ptr
        }
        unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
            let ptr = unsafe { System.alloc_zeroed(layout) };
            if !ptr.is_null() {
                COUNTERS.allocate(layout.size() as u64);
            }
            ptr
        }
        unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
            unsafe { System.dealloc(ptr, layout) };
            COUNTERS.deallocate(layout.size() as u64);
        }
        unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, size: usize) -> *mut u8 {
            let new = unsafe { System.realloc(ptr, layout, size) };
            if !new.is_null() {
                COUNTERS.reallocate(layout.size() as u64, size as u64);
            }
            new
        }
    }
}
#[cfg(feature = "allocation-profiler")]
#[global_allocator]
static ALLOCATOR: allocator::Tracked = allocator::Tracked;

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn tracks_growth_shrink_cleanup_and_existing_baseline() {
        let c = Counters::new();
        c.allocate(100);
        c.reset_peak();
        c.allocate(40);
        c.reallocate(40, 80);
        c.reallocate(80, 20);
        let s = c.snapshot();
        assert_eq!((s.allocation_calls, s.reallocation_calls), (2, 2));
        assert_eq!((s.allocated_bytes, s.freed_bytes), (240, 120));
        assert_eq!((s.live_bytes, s.peak_live_bytes), (120, 180));
        c.deallocate(20);
        assert_eq!(c.snapshot().live_bytes, 100);
        c.reset_peak();
        assert_eq!(c.snapshot().peak_live_bytes, 100);
        c.deallocate(100);
        assert_eq!(c.snapshot().live_bytes, 0);
    }
}
