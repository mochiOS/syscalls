//! waitid uses authenticated child state, never a kernel waitpid fallback.
use super::*;
use mochios_posix_client::{signal_context::SigInfo, wait};

#[unsafe(no_mangle)]
pub extern "C" fn waitid(id_type: c_int, id: u32, output: *mut SigInfo, options: c_int) -> c_int {
    pthread_testcancel();
    let result = (|| {
        let request = wait::request(id_type, id, options)?;
        if output.is_null() {
            return Err(EFAULT);
        }
        let (_, control) = register_current_thread().ok_or(EAGAIN)?;
        let caught = control.nonrestart_signal_generation.load(Ordering::Acquire);
        let client = posix_client().map_err(map_posix_client_error)?;
        let info = loop {
            pthread_testcancel();
            if control.nonrestart_signal_generation.load(Ordering::Acquire) != caught {
                return Err(EINTR);
            }
            let epoch = client
                .thread_signal_epoch()
                .map_err(map_posix_client_error)?;
            pthread_testcancel();
            if control.nonrestart_signal_generation.load(Ordering::Acquire) != caught {
                return Err(EINTR);
            }
            match client.wait_child_info_since(request.selector, request.options, epoch) {
                Ok(info) => break info,
                Err(PosixClientError::Remote(posix_protocol::STATUS_EINTR)) => {
                    drain_pending_signals()?
                }
                Err(error) => return Err(map_posix_client_error(error)),
            }
        };
        if info.result.process_id == 0 {
            user_copy::write(output.cast(), &[0; core::mem::size_of::<SigInfo>()])?;
        } else {
            signal_memory::write_info(output, posix_protocol::SIGNAL_CHLD, wait::origin(info)?)?;
        }
        Ok(0)
    })();
    if result.is_err() {
        pthread_testcancel();
    }
    result_with_errno(result, -1)
}
