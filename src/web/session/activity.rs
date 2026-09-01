use std::time::{Duration, Instant};

/// Session-local activity clocks with distinct lease and diagnostic authority.
pub(super) struct SessionActivity {
    last_peer: Instant,
    last_progress: Instant,
}

impl SessionActivity {
    /// Starts both activity clocks at the same session creation instant.
    pub(super) fn new(now: Instant) -> Self {
        Self {
            last_peer: now,
            last_progress: now,
        }
    }

    /// Records one validated peer operation and returns the preceding peer gap.
    pub(super) fn touch_peer(&mut self, now: Instant) -> Duration {
        let gap = now.saturating_duration_since(self.last_peer);
        self.last_peer = now;
        self.last_progress = now;
        gap
    }

    /// Records server-side carrier progress without extending the peer lease.
    pub(super) fn touch_progress(&mut self, now: Instant) {
        self.last_progress = now;
    }

    /// Returns elapsed time since the latest validated peer operation.
    pub(super) fn peer_idle(&self, now: Instant) -> Duration {
        now.saturating_duration_since(self.last_peer)
    }

    /// Returns elapsed time since the latest carrier-side progress.
    pub(super) fn progress_idle(&self, now: Instant) -> Duration {
        now.saturating_duration_since(self.last_progress)
    }
}
