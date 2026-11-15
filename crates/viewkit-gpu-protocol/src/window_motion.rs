//! Renderer-independent first-frame window reveal. Geometry and input remain fixed.

/// Duration of the standard ease-out window reveal, in milliseconds.
pub const OPEN_DURATION_MS: u64 = 180;
/// Maximum interval between reveal frames; idle windows require no wakeups.
pub const FRAME_INTERVAL_MS: u64 = 16;

/// Bounded, allocation-free first-frame reveal shared by desktop backends.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Opening {
    started_at: Option<u64>,
    opacity: u8,
    complete: bool,
}

impl Opening {
    /// Creates an already visible window, useful for restored state and fixtures.
    pub const fn visible() -> Self {
        Self {
            started_at: None,
            opacity: 255,
            complete: true,
        }
    }
    /// Hides a newly created window until its first real content frame is ready.
    pub const fn pending() -> Self {
        Self {
            started_at: None,
            opacity: 0,
            complete: false,
        }
    }
    /// Advances from the first ready frame. `immediate` bypasses motion without
    /// postponing visibility, including protected presentation surfaces.
    /// Returns whether the visible opacity changed. Never restarts after settling.
    pub fn advance(&mut self, now_ms: u64, ready: bool, immediate: bool) -> bool {
        if self.complete || !ready {
            return false;
        }
        let before = self.opacity;
        let start = *self.started_at.get_or_insert(now_ms);
        let elapsed = now_ms.saturating_sub(start);
        if immediate || elapsed >= OPEN_DURATION_MS {
            self.opacity = 255;
            self.complete = true;
        } else {
            let remaining = (OPEN_DURATION_MS - elapsed) as f32 / OPEN_DURATION_MS as f32;
            self.opacity = ((1. - remaining * remaining * remaining) * 255. + 0.5) as u8;
        }
        self.opacity != before
    }
    /// Returns the current opacity, with 255 representing the unchanged final image.
    pub const fn opacity(self) -> u8 {
        self.opacity
    }
    /// Whether a ready window still needs reveal frames.
    pub const fn pending_frames(self) -> bool {
        !self.complete
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn waits_for_real_pixels_settles_monotonically_and_never_replays() {
        let mut opening = Opening::pending();
        assert!(!opening.advance(1_000, false, false));
        assert_eq!(opening.opacity(), 0);
        opening.advance(2_000, true, false);
        for t in 1..=OPEN_DURATION_MS {
            let before = opening.opacity();
            opening.advance(2_000 + t, true, false);
            assert!(opening.opacity() >= before);
        }
        assert_eq!(opening.opacity(), 255);
        assert!(!opening.pending_frames());
        assert!(!opening.advance(1, true, false));
        assert!(!opening.advance(4_000, true, false));
    }
    #[test]
    fn reduced_motion_and_protected_windows_are_immediate() {
        let mut opening = Opening::pending();
        assert!(opening.advance(10, true, true));
        assert_eq!(
            opening,
            Opening {
                started_at: Some(10),
                ..Opening::visible()
            }
        );
    }
}
