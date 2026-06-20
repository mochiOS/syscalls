#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
USER_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
WORKSPACE_ROOT="$(cd "${USER_ROOT}/.." && pwd)"
NEWLIB_ROOT="${WORKSPACE_ROOT}/libraries/newlib"
CORE_ROOT="${WORKSPACE_ROOT}/core"

BOOTSTRAP_TARGET="x86_64-elf"
FINAL_TARGET="x86_64-unknown-mochios"
TARGET_JSON="${USER_ROOT}/targets/${FINAL_TARGET}.json"

OUT_ROOT="${WORKSPACE_ROOT}/out/newlib-port"
NEWLIB_BUILD_DIR="${OUT_ROOT}/build-newlib"
INSTALL_ROOT="${OUT_ROOT}/toolchain"
SYSROOT_DIR="${INSTALL_ROOT}/${BOOTSTRAP_TARGET}"
RUNTIME_TARGET_DIR="${OUT_ROOT}/cargo-target"
HELLO_DIR="${OUT_ROOT}/hello"
HELLO_C="${USER_ROOT}/libc-port/tests/hello.c"
CRT0_S="${USER_ROOT}/runtime/crt0.S"
LINKER_SCRIPT="${USER_ROOT}/runtime/linker.ld"
SERIAL_LOG="${OUT_ROOT}/serial.log"

need_cmd() {
    command -v "$1" >/dev/null 2>&1 || {
        echo "missing command: $1" >&2
        exit 1
    }
}

need_file() {
    [[ -f "$1" ]] || {
        echo "missing file: $1" >&2
        exit 1
    }
}

if [[ ! -d "${WORKSPACE_ROOT}/.repo" ]]; then
    echo "not a repo workspace: ${WORKSPACE_ROOT}" >&2
    exit 1
fi

need_file "${NEWLIB_ROOT}/configure"
need_file "${USER_ROOT}/Cargo.toml"
need_file "${TARGET_JSON}"
need_file "${HELLO_C}"
need_file "${CRT0_S}"
need_file "${LINKER_SCRIPT}"
need_file "${CORE_ROOT}/scripts/rootfs.sh"
need_file "${CORE_ROOT}/scripts/signature_db.pl"

need_cmd cargo
need_cmd make
need_cmd readelf
need_cmd perl
need_cmd qemu-system-x86_64
need_cmd mke2fs
need_cmd mkfs.fat
need_cmd mmd
need_cmd mcopy
need_cmd truncate
need_cmd tee
need_cmd sed
need_cmd wc
need_cmd x86_64-elf-gcc
need_cmd x86_64-elf-ar
need_cmd x86_64-elf-ranlib

mkdir -p "${OUT_ROOT}" "${HELLO_DIR}" "${RUNTIME_TARGET_DIR}"

echo "[test] user existing tests"
cargo +nightly-2026-05-14 test \
    --manifest-path "${USER_ROOT}/Cargo.toml" \
    -p mochi-user-syscall

rm -rf "${NEWLIB_BUILD_DIR}" "${INSTALL_ROOT}"
mkdir -p "${NEWLIB_BUILD_DIR}" "${INSTALL_ROOT}"

echo "[build] configure newlib"
(
    cd "${NEWLIB_BUILD_DIR}"
    env \
        CC_FOR_TARGET=x86_64-elf-gcc \
        AR_FOR_TARGET=x86_64-elf-ar \
        RANLIB_FOR_TARGET=x86_64-elf-ranlib \
        "${NEWLIB_ROOT}/configure" \
        --target="${BOOTSTRAP_TARGET}" \
        --prefix="${INSTALL_ROOT}" \
        --disable-binutils \
        --disable-gas \
        --disable-gdb \
        --disable-gprof \
        --disable-libgloss \
        --disable-multilib \
        --disable-nls \
        --disable-shared \
        --disable-sim \
        --disable-werror \
        --disable-newlib-supplied-syscalls \
        --enable-newlib-multithread=no \
        --enable-newlib-retargetable-locking
)

echo "[build] newlib"
make -C "${NEWLIB_BUILD_DIR}" -j"$(nproc)" all-target-newlib

echo "[build] install newlib"
make -C "${NEWLIB_BUILD_DIR}" install-target-newlib

echo "[build] mochiOS runtime"
cargo +nightly-2026-05-14 build \
    -Z json-target-spec \
    -Z build-std=core,compiler_builtins \
    --manifest-path "${USER_ROOT}/Cargo.toml" \
    --package mochi-user-newlib-runtime \
    --release \
    --target "${TARGET_JSON}" \
    --target-dir "${RUNTIME_TARGET_DIR}"

RUNTIME_LIB="${RUNTIME_TARGET_DIR}/${FINAL_TARGET}/release/libmochi_user_newlib_runtime.a"
CRT0_O="${HELLO_DIR}/crt0.o"
HELLO_O="${HELLO_DIR}/hello.o"
HELLO_ELF="${HELLO_DIR}/hello.elf"
HELLO_MAP="${HELLO_DIR}/hello.map"

need_file "${RUNTIME_LIB}"

echo "[build] crt0"
x86_64-elf-gcc -c "${CRT0_S}" -o "${CRT0_O}"

echo "[build] hello.c"
x86_64-elf-gcc \
    --sysroot="${SYSROOT_DIR}" \
    -isystem "${SYSROOT_DIR}/include" \
    -ffreestanding \
    -O2 \
    -c "${HELLO_C}" \
    -o "${HELLO_O}"

echo "[link] hello.elf"
x86_64-elf-gcc \
    --sysroot="${SYSROOT_DIR}" \
    -L"${SYSROOT_DIR}/lib" \
    -static \
    -nostdlib \
    -nostartfiles \
    -Wl,-T,"${LINKER_SCRIPT}" \
    -Wl,-no-pie \
    -Wl,-z,noexecstack \
    -Wl,-Map,"${HELLO_MAP}" \
    -Wl,--start-group \
    "${CRT0_O}" \
    "${HELLO_O}" \
    "${RUNTIME_LIB}" \
    -lc \
    -lm \
    -lgcc \
    -Wl,--end-group \
    -o "${HELLO_ELF}"

echo "[check] readelf -h"
readelf -h "${HELLO_ELF}"
echo "[check] readelf -l"
readelf -l "${HELLO_ELF}"
echo "[check] readelf -s"
readelf -s "${HELLO_ELF}"

echo "[check] unresolved symbols"
if readelf -sW "${HELLO_ELF}" | grep ' UND '; then
    echo "unresolved symbols remain" >&2
    exit 1
fi

TARGET_DIR="${CORE_ROOT}/target/uefi"
RUN_ID="newlib-$(date +%s)-$$"
RUN_DIR="${TARGET_DIR}/run-${RUN_ID}"
ESP_DIR="${RUN_DIR}/esp"
ESP_IMG="${RUN_DIR}/esp.img"
INITFS_STAGE="${RUN_DIR}/initfs-root"
ROOTFS_STAGE="${RUN_DIR}/rootfs-root"
OVMF_CODE="${OVMF_CODE:-/usr/share/OVMF/OVMF_CODE_4M.fd}"
OVMF_VARS_TEMPLATE="${OVMF_VARS_TEMPLATE:-/usr/share/OVMF/OVMF_VARS_4M.fd}"
OVMF_VARS="${RUN_DIR}/OVMF_VARS_4M.fd"
SIGNATURE_DB_STAGE="${TARGET_DIR}/signature.db"

need_file "${OVMF_CODE}"
need_file "${OVMF_VARS_TEMPLATE}"

mkdir -p "${TARGET_DIR}" "${ESP_DIR}/EFI/BOOT" "${INITFS_STAGE}"

echo "[build] kernel"
cargo build \
    --locked \
    --release \
    --target x86_64-unknown-none \
    --features kernel-bin \
    --manifest-path "${CORE_ROOT}/Cargo.toml"

echo "[build] bootloader"
cargo build \
    --locked \
    --release \
    --target x86_64-unknown-uefi \
    --target-dir "${TARGET_DIR}/boot-build" \
    --manifest-path "${CORE_ROOT}/examples/boot/Cargo.toml"

KERNEL_BIN="${CORE_ROOT}/target/x86_64-unknown-none/release/kernel"
BOOT_BIN="$(find "${TARGET_DIR}/boot-build/x86_64-unknown-uefi/release" -maxdepth 1 -type f \( -name 'boot' -o -name 'boot.efi' \) | head -n 1)"

need_file "${KERNEL_BIN}"
need_file "${BOOT_BIN}"

rm -rf "${ESP_DIR}" "${INITFS_STAGE}" "${ROOTFS_STAGE}"
mkdir -p "${ESP_DIR}/EFI/BOOT" "${INITFS_STAGE}"

install -m 0644 "${KERNEL_BIN}" "${ESP_DIR}/kernel"
install -m 0644 "${BOOT_BIN}" "${ESP_DIR}/EFI/BOOT/BOOTX64.EFI"
install -m 0755 "${HELLO_ELF}" "${INITFS_STAGE}/core.service"
install -m 0755 "${HELLO_ELF}" "${INITFS_STAGE}/hello.bin"

echo "[build] signature db"
perl "${CORE_ROOT}/scripts/signature_db.pl" \
    --output "${SIGNATURE_DB_STAGE}" \
    --entry "core.service=${HELLO_ELF}" \
    --entry "/hello.bin=${HELLO_ELF}"

echo "[build] rootfs"
ROOTFS_SOURCE_DIR="${CORE_ROOT}/examples/fs/rootfs" \
INITFS_STAGE="${INITFS_STAGE}" \
ROOTFS_STAGE="${ROOTFS_STAGE}" \
ROOTFS_IMG="${TARGET_DIR}/rootfs.img" \
ROOTFS_CLEAN_INITFS=0 \
SIGNATURE_DB_SRC="${SIGNATURE_DB_STAGE}" \
bash "${CORE_ROOT}/scripts/rootfs.sh"

echo "[build] initfs"
truncate -s 16M "${TARGET_DIR}/initfs.img"
mke2fs -q -t ext2 -b 1024 -d "${INITFS_STAGE}" -F "${TARGET_DIR}/initfs.img"

install -m 0644 "${TARGET_DIR}/initfs.img" "${ESP_DIR}/initfs.img"
install -m 0644 "${TARGET_DIR}/rootfs.img" "${ESP_DIR}/rootfs.img"

echo "[build] ESP"
rm -f "${ESP_IMG}"
truncate -s 64M "${ESP_IMG}"
mkfs.fat -F 32 -n EFI "${ESP_IMG}"
MTOOLS_SKIP_CHECK=1 mmd -i "${ESP_IMG}" ::/EFI
MTOOLS_SKIP_CHECK=1 mmd -i "${ESP_IMG}" ::/EFI/BOOT
MTOOLS_SKIP_CHECK=1 mcopy -i "${ESP_IMG}" "${ESP_DIR}/kernel" ::/kernel
MTOOLS_SKIP_CHECK=1 mcopy -i "${ESP_IMG}" "${ESP_DIR}/initfs.img" ::/initfs
MTOOLS_SKIP_CHECK=1 mcopy -i "${ESP_IMG}" "${ESP_DIR}/rootfs.img" ::/rootfs
MTOOLS_SKIP_CHECK=1 mcopy -i "${ESP_IMG}" "${ESP_DIR}/EFI/BOOT/BOOTX64.EFI" ::/EFI/BOOT/BOOTX64.EFI
cp "${OVMF_VARS_TEMPLATE}" "${OVMF_VARS}"

: > "${SERIAL_LOG}"
QEMU_ARGS=(
    -machine q35
    -m 512M
    -smp 4
    -cpu qemu64
    -serial stdio
    -display none
    -monitor none
    -no-reboot
    -drive "if=pflash,format=raw,readonly=on,file=${OVMF_CODE}"
    -drive "if=pflash,format=raw,file=${OVMF_VARS}"
    -drive "format=raw,file=${ESP_IMG}"
)

echo "[run] qemu"
qemu-system-x86_64 "${QEMU_ARGS[@]}" > >(tee -a "${SERIAL_LOG}") 2>&1 &
QEMU_PID=$!

cleanup() {
    kill "${QEMU_PID}" 2>/dev/null || true
    wait "${QEMU_PID}" 2>/dev/null || true
}
trap cleanup EXIT

HELLO_FOUND=0
EXIT_FOUND=0
NEXT_LINE=1
for _ in $(seq 1 600); do
    while IFS= read -r line; do
        if [[ "${line}" == *"hello from mochiOS, argc="* ]]; then
            HELLO_FOUND=1
        fi
        if [[ "${line}" == *"Process exiting with code: 0"* ]]; then
            EXIT_FOUND=1
        fi
    done < <(sed -n "${NEXT_LINE},\$p" "${SERIAL_LOG}")
    NEXT_LINE="$(($(wc -l < "${SERIAL_LOG}") + 1))"
    if [[ "${HELLO_FOUND}" -eq 1 && "${EXIT_FOUND}" -eq 1 ]]; then
        break
    fi
    if ! kill -0 "${QEMU_PID}" 2>/dev/null; then
        break
    fi
    sleep 0.1
done

if [[ "${HELLO_FOUND}" -ne 1 ]]; then
    echo "hello output was not observed" >&2
    exit 1
fi
if [[ "${EXIT_FOUND}" -ne 1 ]]; then
    echo "process exit code was not observed" >&2
    exit 1
fi

kill "${QEMU_PID}" 2>/dev/null || true
wait "${QEMU_PID}" 2>/dev/null || true
trap - EXIT

echo "[done] hello.elf=${HELLO_ELF}"
