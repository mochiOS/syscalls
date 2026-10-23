//! Snapshot the pathname and retain root/cwd authority without opening target
//! data. Namespace traversal and limits observation happen in one provider call.
use super::*;

#[unsafe(no_mangle)]
pub extern "C" fn pathconf(path: *const c_char, name: c_int) -> CLong {
    let result = path_io::at(-2, path, |base, path| {
        if file_configuration::terminal_selector(name) {
            let limits = posix_client()
                .map_err(map_posix_client_error)?
                .terminal_limits_at(base, path)
                .map_err(map_posix_client_error)?;
            return file_configuration::terminal_configuration_value(limits, name);
        }
        if let Some(value) = mochios_posix_client::configuration::file_option(name) {
            // The option is unavailable for every object, but pathname
            // existence/search and root confinement must still be checked.
            posix_client()
                .map_err(map_posix_client_error)?
                .stat_at(base, 0, path)
                .map_err(map_posix_client_error)?;
            return Ok(value);
        }
        file_configuration::filesystem_selector(name)?;
        let limits = posix_client()
            .map_err(map_posix_client_error)?
            .path_limits_at(base, path)
            .map_err(map_posix_client_error)?;
        file_configuration::filesystem_value(limits, name)
    });
    result_with_errno(result, -1)
}
