//! Shared continuous rounded-rectangle geometry (CPU, GPU, clipping and input).
//!
//! For FIXED arc length L, minimizing integral (kappa')^2 with zero endpoint
//! curvature and a quarter turn gives kappa = 3*pi*s*(L-s)/L^3. This is not an
//! optimum over unrestricted arc lengths. Radius is the straight-edge setback.
//! Tables are integrated offline; runtime uses only polynomial evaluation and
//! lookup. No Figma smoothing parameter, circular arcs, or per-pixel integration.

#[path = "continuous_corner_data.rs"]
mod data;

pub const ARC_LENGTH: f64 = 1.6525000895846302;
pub type Point = (f32, f32);

#[derive(Clone, Copy, Debug)]
pub struct Cubic {
    pub start: Point,
    pub control1: Point,
    pub control2: Point,
    pub end: Point,
}
impl Cubic {
    pub fn at(self, t: f32) -> Point {
        let u = 1.0 - t;
        let eval =
            |a, b, c, d| u * u * u * a + 3.0 * u * u * t * b + 3.0 * u * t * t * c + t * t * t * d;
        (
            eval(self.start.0, self.control1.0, self.control2.0, self.end.0),
            eval(self.start.1, self.control1.1, self.control2.1, self.end.1),
        )
    }
}

/// Normalized table sample, including the exact straight-edge endpoints.
pub fn sample(index: usize) -> Point {
    let n = data::NODES[index.min(1024)];
    (n[0] as f32, n[1] as f32)
}

/// Hermite position/tangent interpolation. The short first/last intervals have
/// collinear endpoint controls, making the straight-edge join exactly G2.
pub fn cubic(first: usize, last: usize) -> Cubic {
    let a = data::NODES[first];
    let b = data::NODES[last];
    let handle = ARC_LENGTH * (last - first) as f64 / 1024.0 / 3.0;
    let mut c1 = (a[0] + handle * a[2], a[1] + handle * a[3]);
    let mut c2 = (b[0] - handle * b[2], b[1] - handle * b[3]);
    if first == 0 {
        let h = b[1] / b[3];
        c2 = (b[0] - h * b[2], 0.0);
    }
    if last == 1024 {
        let h = (1.0 - a[0]) / a[2];
        c1 = (1.0, a[1] + h * a[3]);
    }
    Cubic {
        start: (a[0] as f32, a[1] as f32),
        control1: (c1.0 as f32, c1.1 as f32),
        control2: (c2.0 as f32, c2.1 as f32),
        end: (b[0] as f32, b[1] as f32),
    }
}

/// Number of polygon segments per corner. kappa_max * L^2 / (8*n^2)
/// bounds the chord error by < 0.08 physical pixels. Keeping a dyadic grid
/// makes all rendering backends use exactly the same precomputed samples.
pub fn polygon_segments(physical_radius: f32) -> usize {
    let r = if physical_radius.is_finite() {
        physical_radius.max(0.0)
    } else {
        0.0
    };
    let mut n = 8;
    while n < 1024 && 0.98 * r / (n * n) as f32 > 0.08 {
        n *= 2;
    }
    n
}

/// Conservatively measured Hermite error bounds on the normalized curve.
pub fn bezier_segments(physical_radius: f32) -> usize {
    for (n, error) in [(8, 0.00004), (16, 0.000003), (32, 0.0000004)] {
        if physical_radius * error < 0.025 {
            return n;
        }
    }
    64
}

#[derive(Clone, Copy, Debug)]
pub struct RoundedRect {
    /// x, y, width, height
    pub bounds: [f32; 4],
    /// top-left, top-right, bottom-right, bottom-left
    pub radii: [f32; 4],
}
impl RoundedRect {
    pub fn new(bounds: [f32; 4], radii: [f32; 4]) -> Self {
        if !bounds.iter().all(|v| v.is_finite())
            || bounds[2] <= 0.0
            || bounds[3] <= 0.0
            || !(bounds[0] + bounds[2]).is_finite()
            || !(bounds[1] + bounds[3]).is_finite()
        {
            return Self {
                bounds: [0.0; 4],
                radii: [0.0; 4],
            };
        }
        let mut r = radii.map(|v| if v.is_finite() { v.max(0.0) } else { 0.0 });
        let [_, _, w, h] = bounds;
        // f64 sums prevent finite f32 radii from overflowing before scaling.
        let mut scale = 1.0_f64;
        for (edge, a, b) in [(w, 0, 1), (h, 1, 2), (w, 2, 3), (h, 3, 0)] {
            let sum = r[a] as f64 + r[b] as f64;
            if sum > 0.0 {
                scale = scale.min(edge as f64 / sum);
            }
        }
        r = r.map(|v| (v as f64 * scale) as f32);
        Self { bounds, radii: r }
    }
    pub fn uniform(bounds: [f32; 4], radius: f32) -> Self {
        Self::new(bounds, [radius; 4])
    }
    pub fn max_radius(self) -> f32 {
        self.radii.into_iter().fold(0.0, f32::max)
    }
    pub fn is_empty(self) -> bool {
        self.bounds[2] <= 0.0 || self.bounds[3] <= 0.0
    }

    /// Rotate the normalized curve clockwise around each corner. Corner order
    /// is top-right, bottom-right, bottom-left, top-left, matching GPU winding.
    pub fn corner_point(self, corner: usize, p: Point) -> Point {
        let [x, y, w, h] = self.bounds;
        let r = self.radii[(corner + 1) % 4];
        match corner {
            0 => (x + w - r + r * p.0, y + r * p.1),
            1 => (x + w - r * p.1, y + h - r + r * p.0),
            2 => (x + r - r * p.0, y + h - r * p.1),
            _ => (x + r * p.1, y + r - r * p.0),
        }
    }
    pub fn for_each_cubic(self, segments: usize, mut emit: impl FnMut(usize, Cubic)) {
        if self.is_empty() {
            return;
        }
        let n = segments.clamp(8, 64).next_power_of_two();
        let stride = 1024 / n;
        for corner in 0..4 {
            let mut first = 0;
            for last in core::iter::once(1)
                .chain((1..n).map(|i| i * stride))
                .chain([1023, 1024])
            {
                let c = cubic(first, last);
                emit(
                    corner,
                    Cubic {
                        start: self.corner_point(corner, c.start),
                        control1: self.corner_point(corner, c.control1),
                        control2: self.corner_point(corner, c.control2),
                        end: self.corner_point(corner, c.end),
                    },
                );
                first = last;
            }
        }
    }
    pub fn for_each_point(self, segments: usize, mut emit: impl FnMut(Point)) {
        if self.is_empty() {
            return;
        }
        let n = segments.clamp(8, 1024).next_power_of_two();
        for corner in 0..4 {
            for i in 0..=n {
                emit(self.corner_point(corner, sample(i * 1024 / n)));
            }
        }
    }
    /// Parallel contour at a signed outward distance, using reference normals.
    /// Endpoints shared by capsule corners have identical normals, avoiding
    /// zero-length-edge artifacts when constructing antialiased stroke rings.
    pub fn for_each_offset_point(self, segments: usize, offset: f32, mut emit: impl FnMut(Point)) {
        if self.is_empty() {
            return;
        }
        let n = segments.clamp(8, 1024).next_power_of_two();
        for corner in 0..4 {
            for i in 0..=n {
                let index = i * 1024 / n;
                let node = data::NODES[index];
                let (c, s) = (node[2] as f32, node[3] as f32);
                let normal = match corner {
                    0 => (s, -c),
                    1 => (c, s),
                    2 => (-s, c),
                    _ => (-c, -s),
                };
                let p = self.corner_point(corner, sample(index));
                emit((p.0 + normal.0 * offset, p.1 + normal.1 * offset));
            }
        }
    }

    pub fn contains(self, p: Point) -> bool {
        let [x, y, w, h] = self.bounds;
        if self.is_empty()
            || !p.0.is_finite()
            || !p.1.is_finite()
            || p.0 < x
            || p.1 < y
            || p.0 > x + w
            || p.1 > y + h
        {
            return false;
        }
        // For any point in a corner square, reflect to the top-right model.
        for (dx, dy, r) in [
            (p.0 - x, p.1 - y, self.radii[0]),
            (x + w - p.0, p.1 - y, self.radii[1]),
            (x + w - p.0, y + h - p.1, self.radii[2]),
            (p.0 - x, y + h - p.1, self.radii[3]),
        ] {
            if r > 0.0 && dx < r && dy < r {
                let (u, v) = (1.0 - dx / r, dy / r);
                return if u > 0.76794547 {
                    u <= 1.0 - boundary_y(1.0 - v)
                } else {
                    v >= boundary_y(u)
                };
            }
        }
        true
    }
}

/// Piecewise-linear inverse lookup, not numerical integration. The 1024 chords
/// are within 0.000001 of the normalized reference in Euclidean distance.
fn boundary_y(x: f32) -> f32 {
    let mut low = 0;
    let mut high = 1024;
    while high - low > 1 {
        let mid = (low + high) / 2;
        if data::NODES[mid][0] < x as f64 {
            low = mid;
        } else {
            high = mid;
        }
    }
    let a = data::NODES[low];
    let b = data::NODES[high];
    let t = ((x as f64 - a[0]) / (b[0] - a[0])).clamp(0.0, 1.0);
    (a[1] + (b[1] - a[1]) * t) as f32
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::vec::Vec;
    fn reference(t: f64) -> (f64, f64) {
        let n = 1024;
        let h = t / n as f64;
        let mut x = 0.0;
        let mut y = 0.0;
        for i in 0..=n {
            let u = i as f64 * h;
            let theta = core::f64::consts::FRAC_PI_2 * (3.0 * u * u - 2.0 * u * u * u);
            let weight = if i == 0 || i == n {
                1.0
            } else if i % 2 == 0 {
                2.0
            } else {
                4.0
            };
            x += weight * theta.cos();
            y += weight * theta.sin();
        }
        (x * ARC_LENGTH * h / 3.0, y * ARC_LENGTH * h / 3.0)
    }
    fn curvature(c: Cubic, t: f64) -> f64 {
        let axis = |a: f32, b: f32, c: f32, d: f32| {
            let (a, b, c, d) = (a as f64, b as f64, c as f64, d as f64);
            (
                3.0 * ((1.0 - t).powi(2) * (b - a)
                    + 2.0 * (1.0 - t) * t * (c - b)
                    + t * t * (d - c)),
                6.0 * ((1.0 - t) * (c - 2.0 * b + a) + t * (d - 2.0 * c + b)),
            )
        };
        let (dx, ddx) = axis(c.start.0, c.control1.0, c.control2.0, c.end.0);
        let (dy, ddy) = axis(c.start.1, c.control1.1, c.control2.1, c.end.1);
        (dx * ddy - dy * ddx) / (dx * dx + dy * dy).powf(1.5)
    }
    #[test]
    fn reference_endpoints_symmetry_turn_and_curvature() {
        assert_eq!(sample(0), (0.0, 0.0));
        assert_eq!(sample(1024), (1.0, 1.0));
        let end = reference(1.0);
        assert!((end.0 - 1.0).abs() < 1e-11 && (end.1 - 1.0).abs() < 1e-11);
        let mut previous = 0.0_f64;
        for i in 0..=1024 {
            let t = i as f64 / 1024.0;
            let theta = core::f64::consts::FRAC_PI_2 * (3.0 * t * t - 2.0 * t * t * t);
            let k = 3.0 * core::f64::consts::PI * t * (1.0 - t) / ARC_LENGTH;
            assert!(k >= 0.0);
            if i <= 512 {
                assert!(k >= previous);
            } else {
                assert!(k <= previous);
            }
            previous = k;
            let a = sample(i);
            let b = sample(1024 - i);
            assert!((a.0 + b.1 - 1.0).abs() < 1.2e-7);
            assert!((a.1 + b.0 - 1.0).abs() < 1.2e-7);
            if i == 0 {
                assert_eq!(theta, 0.0);
                assert_eq!(k, 0.0);
            }
            if i == 1024 {
                assert_eq!(theta, core::f64::consts::FRAC_PI_2);
                assert_eq!(k, 0.0);
            }
        }
    }
    #[test]
    fn bezier_position_tangent_and_curvature_errors() {
        for n in [8, 16, 32, 64] {
            let rect = RoundedRect::uniform([0.0, 0.0, 2.0, 2.0], 1.0);
            let mut curves = Vec::new();
            rect.for_each_cubic(n, |corner, c| {
                if corner == 0 {
                    curves.push(c)
                }
            });
            let mut indices = std::vec![0, 1];
            indices.extend((1..n).map(|i| i * 1024 / n));
            indices.extend([1023, 1024]);
            let mut worst = 0.0_f64;
            for (c, pair) in curves.iter().zip(indices.windows(2)) {
                let (a, b) = (pair[0] as f64 / 1024.0, pair[1] as f64 / 1024.0);
                for j in 0..=64 {
                    let u = j as f64 / 64.0;
                    let t = a + (b - a) * u;
                    let q = c.at(u as f32);
                    let p = reference(t);
                    worst = worst.max(
                        ((q.0 as f64 - 1.0 - p.0).powi(2) + (q.1 as f64 - p.1).powi(2)).sqrt(),
                    );
                    if j == 0 || j == 64 {
                        let tangent = if j == 0 {
                            (c.control1.0 - c.start.0, c.control1.1 - c.start.1)
                        } else {
                            (c.end.0 - c.control2.0, c.end.1 - c.control2.1)
                        };
                        let theta = core::f64::consts::FRAC_PI_2 * (3.0 * t * t - 2.0 * t * t * t);
                        let cross = tangent.0 as f64 * theta.sin() - tangent.1 as f64 * theta.cos();
                        assert!(cross.abs() < 2e-7, "tangent {n} {t} {cross}");
                        let expected = 3.0 * core::f64::consts::PI * t * (1.0 - t) / ARC_LENGTH;
                        // f32 endpoint coordinates magnify second differences on
                        // the tiny G2 end intervals; verify them separately below.
                        if b - a > 0.01 {
                            assert!(
                                (curvature(*c, u) - expected).abs() < 0.035,
                                "curvature {n} {t}: {} vs {expected}",
                                curvature(*c, u)
                            );
                        }
                    }
                }
            }
            let bound = match n {
                8 => 0.00004,
                16 => 0.000003,
                32 => 0.0000004,
                _ => 0.0000004,
            };
            std::println!("segments={n}, max normalized position error={worst}");
            assert!(worst < bound, "{n}: {worst}");
            assert_eq!(curvature(curves[0], 0.0), 0.0);
            assert_eq!(curvature(*curves.last().unwrap(), 1.0), 0.0);
        }
    }
    #[test]
    fn physical_polygon_accuracy_and_hit_test_agree() {
        for physical_radius in [0.1, 1.0, 4.0, 16.0, 30.0, 128.0, 1024.0, 8192.0, 32768.0] {
            let n = polygon_segments(physical_radius);
            for i in 0..n {
                let a = sample(i * 1024 / n);
                let b = sample((i + 1) * 1024 / n);
                let p = reference((i as f64 + 0.5) / n as f64);
                let dx = (b.0 - a.0) as f64;
                let dy = (b.1 - a.1) as f64;
                let distance =
                    ((p.0 - a.0 as f64) * dy - (p.1 - a.1 as f64) * dx).abs() / dx.hypot(dy);
                assert!(distance * (physical_radius as f64) < 0.081);
            }
        }
        let r = RoundedRect::uniform([0.0, 0.0, 100.0, 60.0], 20.0);
        for i in 1..1024 {
            let p = r.corner_point(0, sample(i));
            let t = i as f64 / 1024.0;
            let theta = core::f64::consts::FRAC_PI_2 * (3.0 * t * t - 2.0 * t * t * t);
            let normal = (-theta.sin() as f32 * 0.002, theta.cos() as f32 * 0.002);
            assert!(r.contains((p.0 + normal.0, p.1 + normal.1)));
            assert!(!r.contains((p.0 - normal.0, p.1 - normal.1)));
        }
    }
    #[test]
    fn radii_zero_capsules_asymmetry_and_invalid_values() {
        let r = RoundedRect::new([0.0, 0.0, 100.0, 30.0], [40.0, 30.0, 20.0, 10.0]);
        assert_eq!(r.radii, [24.0, 18.0, 12.0, 6.0]);
        let square = RoundedRect::uniform([0.0, 0.0, 10.0, 10.0], 0.0);
        assert!(square.contains((0.0, 0.0)));
        let pill = RoundedRect::uniform([0.0, 0.0, 100.0, 30.0], 9999.0);
        assert_eq!(pill.radii, [15.0; 4]);
        assert!(!pill.contains((0.0, 0.0)));
        assert!(pill.contains((50.0, 0.0)));
        for v in [f32::NAN, f32::INFINITY, f32::NEG_INFINITY, -1.0] {
            assert_eq!(
                RoundedRect::uniform([0.0, 0.0, 10.0, 10.0], v).radii,
                [0.0; 4]
            );
            assert!(!RoundedRect::uniform([0.0, 0.0, v, 10.0], 2.0).contains((0.0, 0.0)));
            assert!(!pill.contains((v, v)));
        }
        let huge = RoundedRect::uniform([0.0, 0.0, 100.0, 30.0], f32::MAX);
        assert_eq!(huge.radii, [15.0; 4]);
    }
}
