//! Interpreter selection is POSIX userspace policy, never a kernel fallback.
use super::*;

pub(super) fn replace(
    candidate: *const c_char,
    argv: *const *const c_char,
    envp: *const *const c_char,
) -> Result<(), c_int> {
    io_resources::with_initialized(
        || Ok(exec_inputs::Inputs::new()),
        |inputs| inputs.capture(candidate, argv, envp),
        |inputs| {
            let mut original = [ptr::null(); MAX_EXEC_VECTOR_ENTRIES];
            let mut environment = [ptr::null(); MAX_EXEC_VECTOR_ENTRIES];
            let (count, _) = inputs.c_vectors(&mut original, &mut environment);
            let arguments = count.saturating_sub(1);
            // Reserve argv[0], the script operand, and the terminating NULL.
            if arguments > MAX_EXEC_VECTOR_ENTRIES - 3 {
                return Err(E2BIG);
            }
            let mut script = [0; MAX_EXECUTABLE_PATH_LEN + 2];
            let path = inputs.path();
            // A PATH entry can be empty. Keep a leading '-' in the filename
            // from becoming an option to sh while retaining the same file.
            let prefix = if path.first() == Some(&b'-') { 2 } else { 0 };
            if prefix != 0 {
                script[..prefix].copy_from_slice(b"./");
            }
            script[prefix..prefix + path.len()].copy_from_slice(path);
            let mut shell_arguments = [ptr::null(); MAX_EXEC_VECTOR_ENTRIES];
            shell_arguments[0] = c"sh".as_ptr();
            shell_arguments[1] = script.as_ptr().cast();
            if arguments != 0 {
                shell_arguments[2..2 + arguments].copy_from_slice(&original[1..count]);
            }
            // Direct image replacement, with the same FD/capability/execute
            // admission path. Do not recursively search PATH for an interpreter.
            execve_with_launch_context(
                c"/bin/sh".as_ptr(),
                shell_arguments.as_ptr(),
                environment.as_ptr(),
            )
        },
    )
}
