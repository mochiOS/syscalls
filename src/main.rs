use swiftlib::{keyboard, mouse, time, vga};

const BG_COLOR: u32 = 0x001E_1E2E;
const CURSOR_COLOR: u32 = 0x00FF_FFFF;
const CURSOR_SIZE: i32 = 4;

struct KagamiServer {
    fb_ptr: *mut u32,
    width: i32,
    height: i32,
    stride: i32,
    cursor_x: i32,
    cursor_y: i32,
}

impl KagamiServer {
    fn new(fb_ptr: *mut u32, info: vga::FbInfo) -> Self {
        Self {
            fb_ptr,
            width: info.width as i32,
            height: info.height as i32,
            stride: info.stride as i32,
            cursor_x: (info.width / 2) as i32,
            cursor_y: (info.height / 2) as i32,
        }
    }

    fn run(&mut self) {
        self.clear_screen(BG_COLOR);
        self.draw_cursor(self.cursor_x, self.cursor_y, CURSOR_COLOR);
        println!("[KAGAMI] started (ESC to exit)");

        loop {
            self.handle_mouse();
            if self.handle_keyboard_exit() {
                println!("[KAGAMI] exit");
                return;
            }
            time::sleep_ms(8);
        }
    }

    fn handle_keyboard_exit(&mut self) -> bool {
        match keyboard::read_scancode() {
            Some(0x01) => true, // ESC make code (set1)
            _ => false,
        }
    }

    fn handle_mouse(&mut self) {
        loop {
            let packet = match mouse::read_packet() {
                Ok(Some(p)) => p,
                Ok(None) => return,
                Err(_) => return,
            };

            let old_x = self.cursor_x;
            let old_y = self.cursor_y;
            self.cursor_x = clamp_i32(self.cursor_x + packet.dx as i32, 0, self.width - 1);
            self.cursor_y = clamp_i32(self.cursor_y - packet.dy as i32, 0, self.height - 1);

            if self.cursor_x != old_x || self.cursor_y != old_y {
                self.draw_cursor(old_x, old_y, BG_COLOR);
                self.draw_cursor(self.cursor_x, self.cursor_y, CURSOR_COLOR);
            }
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

    fn draw_cursor(&mut self, cx: i32, cy: i32, color: u32) {
        for d in -CURSOR_SIZE..=CURSOR_SIZE {
            self.put_pixel(cx + d, cy, color);
            self.put_pixel(cx, cy + d, color);
        }
    }

    fn put_pixel(&mut self, x: i32, y: i32, color: u32) {
        if x < 0 || y < 0 || x >= self.width || y >= self.height {
            return;
        }
        let idx = (y * self.stride + x) as usize;
        let pixel = color | 0xFF00_0000;
        unsafe {
            self.fb_ptr.add(idx).write_volatile(pixel);
        }
    }
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

    let mut server = KagamiServer::new(fb_ptr, info);
    server.run();
}
