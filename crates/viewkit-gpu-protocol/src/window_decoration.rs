//! Logical geometry shared by ViewKit and protected server-side decorations.
//! These defaults do not change the GPU scene wire format or grant UI authority.

/// Default and minimum title-bar height in logical pixels.
pub const TITLE_BAR_HEIGHT: u32 = 32;
/// Diameter of each circular window-control background in logical pixels.
pub const CONTROL_SIZE: u32 = 28;
/// Horizontal space between window controls in logical pixels.
pub const CONTROL_GAP: u32 = 2;
/// Space after the close control in logical pixels.
pub const CONTROL_INSET: u32 = 6;
/// Minimize, maximize/restore and close controls.
pub const CONTROL_COUNT: u32 = 3;
/// Trailing region reserved for the window system's controls.
pub const CONTROLS_WIDTH: u32 =
    CONTROL_SIZE * CONTROL_COUNT + CONTROL_GAP * (CONTROL_COUNT - 1) + CONTROL_INSET;
/// Size of window-control symbols in logical pixels.
pub const CONTROL_ICON_SIZE: u32 = 14;
/// Clearance between window controls and shell edge-reveal targets.
pub const CONTROL_REVEAL_MARGIN: u32 = 8;
/// Fixed-point scale denominator used by decoration messages.
pub const SCALE_UNIT: u32 = 1024;
/// Smallest accepted decoration scale: one quarter of the logical size.
pub const MIN_SCALE: u32 = SCALE_UNIT / 4;
/// Largest accepted decoration scale: eight times the logical size.
pub const MAX_SCALE: u32 = SCALE_UNIT * 8;

/// Converts a logical extent to physical pixels, rounding outwards.
pub const fn physical_pixels(logical: u32, scale: u32) -> u32 {
    let pixels = (logical as u64 * scale as u64 + SCALE_UNIT as u64 - 1) / SCALE_UNIT as u64;
    if pixels > u32::MAX as u64 {
        u32::MAX
    } else {
        pixels as u32
    }
}
