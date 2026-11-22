//! The threads of [`SearchPool::Dedicated`](super::SearchPool) searches.
//!
//! Starting a thread per worker for every search cost a stamped link
//! request about as much as its grind at the default link cost. Workers
//! park between searches instead and the next search reuses them. A search
//! takes as many parked workers as it needs and starts new threads for the
//! rest, so it never waits for another search to finish: a link key grind
//! running until its deadline, or a discovery stamp, does not hold up the
//! next one. A worker parks again after its search while fewer than one
//! search's worth of workers are parked, and exits otherwise.

use std::any::Any;
use std::panic::{self, AssertUnwindSafe};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc, Condvar, Mutex};

use crate::sync::lock_or_recover;

/// One search, as its workers see it.
trait Task: Send + Sync {
    /// Grind until this search stops, record the outcome, and call `park`
    /// just before the search learns that this worker is done.
    fn run(&self, park: &mut dyn FnMut());
}

type Job = Arc<dyn Task>;

/// Senders of the parked workers.
static PARKED: Mutex<Vec<mpsc::Sender<Job>>> = Mutex::new(Vec::new());

struct Search<T, F> {
    grind: F,
    stop: AtomicBool,
    state: Mutex<State<T>>,
    done: Condvar,
}

struct State<T> {
    result: Option<T>,
    /// Workers that have not finished yet.
    running: usize,
    panic: Option<Box<dyn Any + Send>>,
}

impl<T, F> Task for Search<T, F>
where
    T: Send,
    F: Fn(&AtomicBool) -> Option<T> + Send + Sync,
{
    fn run(&self, park: &mut dyn FnMut()) {
        super::renice_search_thread();
        let outcome = panic::catch_unwind(AssertUnwindSafe(|| (self.grind)(&self.stop)));
        self.stop.store(true, Ordering::Relaxed);
        park();
        let mut state = lock_or_recover(&self.state, "stamp search state");
        match outcome {
            Ok(Some(found)) => {
                if state.result.is_none() {
                    state.result = Some(found);
                }
            }
            Ok(None) => {}
            Err(payload) => {
                if state.panic.is_none() {
                    state.panic = Some(payload);
                }
            }
        }
        state.running = state.running.saturating_sub(1);
        if state.running == 0 {
            self.done.notify_all();
        }
    }
}

/// Run `grind` on `workers` dedicated threads until one of them stops,
/// wait for all of them, and return the result found, if any. A panic in
/// `grind` is resumed here once every worker has stopped.
pub(super) fn search<T, F>(workers: usize, grind: F) -> Option<T>
where
    T: Send + 'static,
    F: Fn(&AtomicBool) -> Option<T> + Send + Sync + 'static,
{
    let search = Arc::new(Search {
        grind,
        stop: AtomicBool::new(false),
        state: Mutex::new(State {
            result: None,
            running: workers,
            panic: None,
        }),
        done: Condvar::new(),
    });
    let mut started = 0;
    for _ in 0..workers {
        if dispatch(Arc::clone(&search) as Job) {
            started += 1;
        }
    }
    if started == 0 {
        log::warn!("could not start stamp search threads; searching on the calling thread");
        return (search.grind)(&search.stop);
    }
    let mut state = lock_or_recover(&search.state, "stamp search state");
    state.running = state
        .running
        .saturating_sub(workers.saturating_sub(started));
    while state.running > 0 {
        state = search
            .done
            .wait(state)
            .unwrap_or_else(|poisoned| poisoned.into_inner());
    }
    if let Some(payload) = state.panic.take() {
        drop(state);
        panic::resume_unwind(payload);
    }
    state.result.take()
}

/// Hand `job` to a parked worker, or to a new one. False when no thread
/// could be started for it.
fn dispatch(job: Job) -> bool {
    let mut job = job;
    loop {
        let parked = lock_or_recover(&PARKED, "stamp search workers").pop();
        match parked {
            Some(worker) => match worker.send(job) {
                Ok(()) => return true,
                // A worker is parked only while it waits for a job, so
                // this does not happen; try the next one.
                Err(mpsc::SendError(returned)) => job = returned,
            },
            None => return start_worker(job),
        }
    }
}

/// Start a worker thread that runs `job` first.
fn start_worker(job: Job) -> bool {
    let (sender, jobs) = mpsc::channel::<Job>();
    let own = sender.clone();
    let spawned = std::thread::Builder::new()
        .spawn(move || work(&jobs, &own))
        .is_ok();
    spawned && sender.send(job).is_ok()
}

/// A worker: run jobs, parking between them while there is room.
fn work(jobs: &mpsc::Receiver<Job>, own: &mpsc::Sender<Job>) {
    while let Ok(job) = jobs.recv() {
        let mut parked = false;
        // Park before the search returns, so a search that follows right
        // after finds this worker parked.
        job.run(&mut || {
            let mut list = lock_or_recover(&PARKED, "stamp search workers");
            if list.len() < super::dedicated_workers() {
                list.push(own.clone());
                parked = true;
            }
        });
        if !parked {
            return;
        }
    }
}

/// Parked workers, for tests.
#[cfg(test)]
pub(super) fn parked() -> usize {
    lock_or_recover(&PARKED, "stamp search workers").len()
}
