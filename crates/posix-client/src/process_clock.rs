//! Named process clocks live below pthread clock IDs and above built-in IDs.
//! PID bytes select POSIX policy only; they never acquire native Handles.
use super::*;
pub const FIRST_ID: u64 = 1 << 31;

pub fn clock_id(pid: u64) -> Option<u64> {
    (pid != 0 && pid <= protocol::process_clock::MAX_PID).then_some(FIRST_ID | pid)
}
pub fn target(id: u64) -> Option<u64> {
    if id > FIRST_ID && id < (FIRST_ID << 1) {
        Some(id & (FIRST_ID - 1))
    } else {
        None
    }
}

pub fn timespec(sample: protocol::process_clock::Sample) -> Result<(i64, i64), i32> {
    if sample.ticks_per_second == 0 {
        return Err(newlib_errno::EIO);
    }
    let ticks = u128::from(sample.user_ticks) + u128::from(sample.kernel_ticks);
    let rate = u128::from(sample.ticks_per_second);
    let seconds = i64::try_from(ticks / rate).map_err(|_| newlib_errno::EOVERFLOW)?;
    let nanos = ((ticks % rate) * 1_000_000_000 / rate) as i64;
    Ok((seconds, nanos))
}

impl<T: Transport> Client<T> {
    pub fn process_cpu_clock(
        &self,
        pid: u64,
    ) -> Result<protocol::process_clock::Sample, ClientError<T::Error>> {
        if pid > protocol::process_clock::MAX_PID {
            return Err(ClientError::RequestTooLarge);
        }
        let mut output = [0; protocol::process_clock::SAMPLE_LEN];
        let length = self.request(
            protocol::OP_PROCESS_CPU_CLOCK,
            0,
            &pid.to_le_bytes(),
            &mut output,
        )?;
        let sample =
            protocol::process_clock::decode(&output[..length]).map_err(ClientError::Protocol)?;
        if pid != 0 && pid != sample.process_id {
            return Err(ClientError::MismatchedResponse);
        }
        Ok(sample)
    }
}
