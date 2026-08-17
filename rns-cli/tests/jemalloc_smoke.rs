#![cfg(not(target_env = "msvc"))]

#[global_allocator]
static GLOBAL: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

#[repr(align(4096))]
struct PageAligned([u8; 4096]);

#[test]
fn jemalloc_honors_large_alignment_and_zero_initialization() {
    let allocation = Box::new(PageAligned([0; 4096]));
    let address = (&*allocation as *const PageAligned) as usize;

    assert_eq!(address % 4096, 0);
    assert!(allocation.0.iter().all(|byte| *byte == 0));
}

#[test]
fn jemalloc_reallocation_preserves_contents_when_growing_and_shrinking() {
    let mut allocation: Vec<u8> = (0..=255).collect();
    allocation.reserve_exact(2 * 1024 * 1024);

    assert_eq!(&allocation[..], &(0..=255).collect::<Vec<_>>());
    allocation.resize(1024 * 1024, 0xA5);
    assert_eq!(&allocation[..=255], &(0..=255).collect::<Vec<_>>());
    assert!(allocation[256..].iter().all(|byte| *byte == 0xA5));

    allocation.truncate(128);
    allocation.shrink_to_fit();
    assert_eq!(&allocation[..], &(0..128).collect::<Vec<_>>());
}

#[test]
fn jemalloc_handles_concurrent_mixed_size_workloads() {
    let workers: Vec<_> = (0..8)
        .map(|worker| {
            std::thread::spawn(move || {
                for round in 0..250 {
                    let len = 1 + ((worker * 997 + round * 257) % 65_536);
                    let mut bytes = vec![worker as u8; len];
                    bytes[len / 2] = round as u8;
                    assert_eq!(bytes[0], worker as u8);
                    assert_eq!(bytes[len / 2], round as u8);
                }
            })
        })
        .collect();

    for worker in workers {
        worker.join().expect("allocation worker panicked");
    }
}
