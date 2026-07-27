use core::time::Duration;

use rustls::pki_types::UnixTime;
use rustls::time_provider::TimeProvider;

#[derive(Clone, Copy, Debug)]
pub struct FixedTimeProvider {
    seconds: Option<u64>,
}

impl FixedTimeProvider {
    pub const fn at(seconds: u64) -> Self {
        Self {
            seconds: Some(seconds),
        }
    }

    pub const fn unavailable() -> Self {
        Self { seconds: None }
    }
}

impl TimeProvider for FixedTimeProvider {
    fn current_time(&self) -> Option<UnixTime> {
        self.seconds
            .map(|seconds| UnixTime::since_unix_epoch(Duration::from_secs(seconds)))
    }
}

#[cfg(any(target_os = "mochios", target_os = "none"))]
#[derive(Clone, Copy, Debug)]
pub struct PlatformTimeProvider;

#[cfg(any(target_os = "mochios", target_os = "none"))]
impl TimeProvider for PlatformTimeProvider {
    fn current_time(&self) -> Option<UnixTime> {
        mochi_user_platform::time::utc_seconds()
            .ok()
            .map(|seconds| UnixTime::since_unix_epoch(Duration::from_secs(seconds)))
    }
}
