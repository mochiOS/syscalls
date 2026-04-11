use swiftlib::{keyboard, mouse, task, vga};

const BG_COLOR: u32 = 0x001E_1E2E;
const MOUSE_SPEED_DIVISOR: i32 = 3;

include!(concat!(env!("OUT_DIR"), "/cursor_pixels.rs"));

struct CursorSprite {
    width: usize,
    height: usize,
    pixels: Vec<u32>, // ARGB8888
}

impl CursorSprite {
    fn from_generated() -> Self {
        Self {
            width: CURSOR_WIDTH,
            height: CURSOR_HEIGHT,
            pixels: CURSOR_PIXELS.to_vec(),
        }
    }
}

struct InputState {
    esc_armed: bool,
    mouse_acc_x: i32,
    mouse_acc_y: i32,
}

impl InputState {
    fn new() -> Self {
        Self {
            esc_armed: false,
            mouse_acc_x: 0,
            mouse_acc_y: 0,
        }
    }

    fn handle_scancode(&mut self, scancode: u8) -> bool {
        match scancode {
            0x01 => {
                self.esc_armed = true;
                false
            }
            0x81 => self.esc_armed,
            _ => false,
        }
    }

    fn consume_mouse(&mut self, packet: mouse::MousePacket) -> Option<(i32, i32)> {
        self.mouse_acc_x += packet.dx as i32;
        self.mouse_acc_y += packet.dy as i32;

        let step_x = self.mouse_acc_x / MOUSE_SPEED_DIVISOR;
        let step_y = self.mouse_acc_y / MOUSE_SPEED_DIVISOR;

        self.mouse_acc_x -= step_x * MOUSE_SPEED_DIVISOR;
        self.mouse_acc_y -= step_y * MOUSE_SPEED_DIVISOR;

        if step_x == 0 && step_y == 0 {
            None
        } else {
            Some((step_x, step_y))
        }
    }
}

struct Renderer {
    fb_ptr: *mut u32,
    width: i32,
    height: i32,
    stride: i32,
    cursor_x: i32,
    cursor_y: i32,
    cursor_sprite: CursorSprite,
    cursor_saved_bg: Vec<u32>,
}

impl Renderer {
    fn new(fb_ptr: *mut u32, info: vga::FbInfo) -> Self {
        let cursor_sprite = CursorSprite::from_generated();
        let cursor_saved_bg = vec![0u32; cursor_sprite.width * cursor_sprite.height];
        Self {
            fb_ptr,
            width: info.width as i32,
            height: info.height as i32,
            stride: info.stride as i32,
            cursor_x: (info.width / 2) as i32,
            cursor_y: (info.height / 2) as i32,
            cursor_sprite,
            cursor_saved_bg,
        }
    }

    fn initialize(&mut self) {
        self.clear_screen(BG_COLOR);
        self.draw_cursor(self.cursor_x, self.cursor_y);
    }

    fn move_cursor_by(&mut self, dx: i32, dy: i32) {
        let old_x = self.cursor_x;
        let old_y = self.cursor_y;
        self.cursor_x = clamp_i32(self.cursor_x + dx, 0, self.width - 1);
        self.cursor_y = clamp_i32(self.cursor_y - dy, 0, self.height - 1);

        if self.cursor_x != old_x || self.cursor_y != old_y {
            self.restore_cursor(old_x, old_y);
            self.draw_cursor(self.cursor_x, self.cursor_y);
        }
    }

    fn clear_screen(&mut self, color: u32) {
        let total = (self.height * self.stride) as usize;
        let pixel = color | 0xFF00_0000;
        for i in 0..total {
            unsafe {
                self.fb_ptr.add(i).write_volatile(pixel);
            }
        }
    }

    fn draw_cursor(&mut self, cx: i32, cy: i32) {
        for sy in 0..self.cursor_sprite.height {
            for sx in 0..self.cursor_sprite.width {
                let sprite_idx = sy * self.cursor_sprite.width + sx;
                let x = cx + sx as i32;
                let y = cy + sy as i32;
                if x < 0 || y < 0 || x >= self.width || y >= self.height {
                    continue;
                }
                let fb_idx = (y * self.stride + x) as usize;
                let dst = unsafe { self.fb_ptr.add(fb_idx).read_volatile() };
                self.cursor_saved_bg[sprite_idx] = dst;
                let src = self.cursor_sprite.pixels[sprite_idx];
                let blended = blend_argb(dst, src);
                unsafe {
                    self.fb_ptr.add(fb_idx).write_volatile(blended);
                }
            }
        }
    }

    fn restore_cursor(&mut self, cx: i32, cy: i32) {
        for sy in 0..self.cursor_sprite.height {
            for sx in 0..self.cursor_sprite.width {
                let sprite_idx = sy * self.cursor_sprite.width + sx;
                let x = cx + sx as i32;
                let y = cy + sy as i32;
                if x < 0 || y < 0 || x >= self.width || y >= self.height {
                    continue;
                }
                let fb_idx = (y * self.stride + x) as usize;
                unsafe {
                    self.fb_ptr
                        .add(fb_idx)
                        .write_volatile(self.cursor_saved_bg[sprite_idx]);
                }
            }
        }
    }
}

struct KagamiApp {
    renderer: Renderer,
    input: InputState,
    warned_mouse_err: bool,
}

impl KagamiApp {
    fn new(renderer: Renderer) -> Self {
        Self {
            renderer,
            input: InputState::new(),
            warned_mouse_err: false,
        }
    }

    fn run(&mut self) {
        self.renderer.initialize();
        println!("[KAGAMI] started (ESC to exit)");

        loop {
            if let Some(sc) = keyboard::read_scancode()
                && self.input.handle_scancode(sc)
            {
                println!("[KAGAMI] exit");
                return;
            }

            match mouse::read_packet_raw() {
                Ok(Some(packet)) => {
                    if let Some((dx, dy)) = self.input.consume_mouse(packet) {
                        self.renderer.move_cursor_by(dx, dy);
                    }
                }
                Ok(None) => task::yield_now(),
                Err(err) => {
                    if !self.warned_mouse_err {
                        eprintln!("[KAGAMI] mouse read error: {}", err as i64);
                        self.warned_mouse_err = true;
                    }
                    task::yield_now();
                }
            }
        }
    }
}

fn blend_argb(dst: u32, src: u32) -> u32 {
    let sa = (src >> 24) & 0xFF;
    if sa == 0 {
        return dst;
    }
    if sa == 0xFF {
        return src | 0xFF00_0000;
    }
    let inv = 255 - sa;
    let sr = (src >> 16) & 0xFF;
    let sg = (src >> 8) & 0xFF;
    let sb = src & 0xFF;
    let dr = (dst >> 16) & 0xFF;
    let dg = (dst >> 8) & 0xFF;
    let db = dst & 0xFF;
    let r = (sr * sa + dr * inv) / 255;
    let g = (sg * sa + dg * inv) / 255;
    let b = (sb * sa + db * inv) / 255;
    0xFF00_0000 | (r << 16) | (g << 8) | b
}

fn clamp_i32(v: i32, min: i32, max: i32) -> i32 {
    if v < min {
        min
    } else if v > max {
        max
    } else {
        v
    }
}

pub fn main() {
    let info = match vga::get_info() {
        Some(i) => i,
        None => {
            eprintln!("[KAGAMI] failed: get framebuffer info");
            return;
        }
    };
    let fb_ptr = match vga::map_framebuffer() {
        Some(p) => p,
        None => {
            eprintln!("[KAGAMI] failed: map framebuffer");
            return;
        }
    };

    let renderer = Renderer::new(fb_ptr, info);
    let mut app = KagamiApp::new(renderer);
    app.run();
}
