//! Convex clipping with a one-pixel coverage ramp, shared by scene producers
//! and the compositor. This does not change the scene wire format.
extern crate alloc;
use alloc::vec::Vec;

/// A premultiplied vertex used only while generating coverage geometry.
#[derive(Clone, Copy, Debug)]
pub struct Vertex {
    /// Position in the caller's coordinate space.
    pub position: [f32; 2],
    /// Texture coordinates, interpolated at generated intersections.
    pub uv: [f32; 2],
    /// Premultiplied RGBA; coverage scales all four channels together.
    pub color: [f32; 4],
}
impl Vertex {
    fn mix(self, other: Self, t: f32) -> Self {
        let mix = |a: f32, b: f32| a + (b - a) * t;
        Self {
            position: core::array::from_fn(|i| mix(self.position[i], other.position[i])),
            uv: core::array::from_fn(|i| mix(self.uv[i], other.uv[i])),
            color: core::array::from_fn(|i| mix(self.color[i], other.color[i])),
        }
    }
}

/// Cached inward half-planes and disjoint coverage regions for a convex clip.
/// Regions are generated once per shape, not once per input triangle.
#[derive(Clone, Debug, PartialEq)]
pub struct Clip {
    edges: Vec<[f32; 3]>,
    fringe: f32,
    interior: Region,
    bands: Vec<([f32; 3], Region)>,
}
#[derive(Clone, Debug, PartialEq)]
struct Region {
    edges: Vec<[f32; 3]>,
    bounds: [f32; 4],
}
impl Region {
    fn new(points: &[Vertex]) -> Self {
        let mut edges = Vec::new();
        let mut bounds = [
            f32::INFINITY,
            f32::INFINITY,
            f32::NEG_INFINITY,
            f32::NEG_INFINITY,
        ];
        for p in points {
            bounds[0] = bounds[0].min(p.position[0]);
            bounds[1] = bounds[1].min(p.position[1]);
            bounds[2] = bounds[2].max(p.position[0]);
            bounds[3] = bounds[3].max(p.position[1]);
        }
        for (a, b) in points
            .iter()
            .zip(points.iter().cycle().skip(1))
            .take(points.len())
        {
            let [x, y] = a.position;
            let dx = b.position[0] - x;
            let dy = b.position[1] - y;
            if dx.abs() + dy.abs() > 0.000001 {
                edges.push([-dy, dx, dy * x - dx * y]);
            }
        }
        Self { edges, bounds }
    }
    fn clip(&self, triangle: [Vertex; 3]) -> Vec<Vertex> {
        if self.edges.len() < 3 {
            return Vec::new();
        }
        let [l, t, r, b] = self.bounds;
        if triangle.iter().all(|v| v.position[0] < l)
            || triangle.iter().all(|v| v.position[0] > r)
            || triangle.iter().all(|v| v.position[1] < t)
            || triangle.iter().all(|v| v.position[1] > b)
        {
            return Vec::new();
        }
        let mut polygon = triangle.to_vec();
        for edge in &self.edges {
            if polygon.iter().all(|v| distance(*edge, v.position) >= 0.0) {
                continue;
            }
            polygon = cut(&polygon, *edge, 0.0, true);
            if polygon.len() < 3 {
                return Vec::new();
            }
        }
        polygon
    }
}
impl Clip {
    /// Builds a convex clip with half a coordinate unit of edge coverage.
    /// Use `for_fringe` when the coordinate space is logical rather than physical.
    pub fn new(points: &[(f32, f32)]) -> Option<Self> {
        Self::for_fringe(points, 0.5)
    }
    /// Builds disjoint full-coverage and nearest-edge regions. `fringe` is half
    /// a physical pixel in the caller's coordinates. Invalid shapes are rejected.
    pub fn for_fringe(points: &[(f32, f32)], fringe: f32) -> Option<Self> {
        if !fringe.is_finite()
            || fringe <= 0.0
            || points.len() < 3
            || points.len() > 4096
            || points.iter().any(|p| !p.0.is_finite() || !p.1.is_finite())
        {
            return None;
        }
        // Translate the area calculation to avoid cancellation when moving a window.
        let origin = points[0];
        let area: f32 = points
            .iter()
            .zip(points.iter().cycle().skip(1))
            .take(points.len())
            .map(|(a, b)| (a.0 - origin.0) * (b.1 - origin.1) - (b.0 - origin.0) * (a.1 - origin.1))
            .sum();
        if area.abs() < 0.00001 || !area.is_finite() {
            return None;
        }
        let sign = if area > 0.0 { 1.0 } else { -1.0 };
        let mut edges = Vec::new();
        let mut bounds = [
            f32::INFINITY,
            f32::INFINITY,
            f32::NEG_INFINITY,
            f32::NEG_INFINITY,
        ];
        for &(x, y) in points {
            bounds[0] = bounds[0].min(x);
            bounds[1] = bounds[1].min(y);
            bounds[2] = bounds[2].max(x);
            bounds[3] = bounds[3].max(y);
        }
        for (a, b) in points
            .iter()
            .zip(points.iter().cycle().skip(1))
            .take(points.len())
        {
            let dx = b.0 - a.0;
            let dy = b.1 - a.1;
            let square = dx * dx + dy * dy;
            if !square.is_finite() {
                return None;
            }
            if square < 0.00000001 {
                continue;
            }
            let mut length = f32::from_bits((square.to_bits() >> 1) + 0x1fc00000);
            for _ in 0..4 {
                length = (length + square / length) * 0.5;
            }
            let nx = -dy / length * sign;
            let ny = dx / length * sign;
            let edge = [nx, ny, -nx * a.0 - ny * a.1];
            // Collinear polygon samples represent the same plane. Keeping one
            // prevents duplicate edge bands and needless coverage intersections.
            if !edges.iter().any(|e: &[f32; 3]| {
                (e[0] - nx).abs() < 0.000001
                    && (e[1] - ny).abs() < 0.000001
                    && (e[2] - edge[2]).abs() < 0.00001
            }) {
                edges.push(edge);
            }
        }
        if edges.len() < 3 || edges.len() > 1024 {
            return None;
        }
        let [l, t, r, b] = bounds;
        let vertex = |(x, y)| Vertex {
            position: [x, y],
            uv: [0.; 2],
            color: [1.; 4],
        };
        let base = alloc::vec![
            vertex((l - fringe, t - fringe)),
            vertex((r + fringe, t - fringe)),
            vertex((r + fringe, b + fringe)),
            vertex((l - fringe, b + fringe))
        ];
        let mut core = base.clone();
        for &edge in &edges {
            core = cut(&core, edge, fringe, true);
            if core.len() < 3 {
                break;
            }
        }
        let interior = Region::new(&core);
        let mut bands = Vec::new();
        for (index, &edge) in edges.iter().enumerate() {
            let mut polygon = cut(&base, edge, -fringe, true);
            polygon = cut(&polygon, edge, fringe, false);
            for (other_index, &other) in edges.iter().enumerate() {
                if index == other_index {
                    continue;
                }
                // Each point belongs to its nearest boundary only. Unlike
                // successive band splitting this cannot grow quadratically.
                let nearest = core::array::from_fn(|i| other[i] - edge[i]);
                polygon = cut(&polygon, nearest, 0.0, true);
                if polygon.len() < 3 {
                    break;
                }
            }
            if polygon.len() >= 3 {
                bands.push((edge, Region::new(&polygon)));
            }
        }
        Some(Self {
            edges,
            fringe,
            interior,
            bands,
        })
    }
    /// Estimated heap bytes retained by this cached geometry, excluding allocator metadata.
    pub fn storage_bytes(&self) -> usize {
        self.edges.capacity() * core::mem::size_of::<[f32; 3]>()
            + self.interior.edges.capacity() * core::mem::size_of::<[f32; 3]>()
            + self.bands.capacity() * core::mem::size_of::<([f32; 3], Region)>()
            + self
                .bands
                .iter()
                .map(|(_, r)| r.edges.capacity() * core::mem::size_of::<[f32; 3]>())
                .sum::<usize>()
    }
    /// Whether a point is beyond the full-coverage boundary.
    pub fn contains_interior(&self, point: [f32; 2], fringe: f32) -> bool {
        self.edges.iter().all(|e| distance(*e, point) >= fringe)
    }
    /// Clips into cached disjoint regions. Only the nearest boundary's one-pixel
    /// band receives alpha; the interior never acquires a large gradient.
    /// `None` requests safe fallback on invalid inputs or geometry-budget failure.
    pub fn triangle(&self, triangle: [Vertex; 3], fringe: f32) -> Option<Vec<[Vertex; 3]>> {
        if (fringe - self.fringe).abs() > 0.000001
            || !fringe.is_finite()
            || triangle.iter().any(|v| {
                v.position
                    .iter()
                    .chain(v.uv.iter())
                    .chain(v.color.iter())
                    .any(|x| !x.is_finite())
            })
        {
            return None;
        }
        let mut output = Vec::new();
        let emit = |polygon: Vec<Vertex>, output: &mut Vec<[Vertex; 3]>| {
            for i in 1..polygon.len().saturating_sub(1) {
                let [a, b, c] = [polygon[0], polygon[i], polygon[i + 1]];
                let area = (b.position[0] - a.position[0]) * (c.position[1] - a.position[1])
                    - (b.position[1] - a.position[1]) * (c.position[0] - a.position[0]);
                if area.abs() > 0.0000001 {
                    output.push([a, b, c]);
                }
            }
        };
        emit(self.interior.clip(triangle), &mut output);
        for (edge, region) in &self.bands {
            let mut polygon = region.clip(triangle);
            for vertex in &mut polygon {
                let coverage =
                    ((distance(*edge, vertex.position) + fringe) / (2.0 * fringe)).clamp(0., 1.);
                for c in &mut vertex.color {
                    *c *= coverage;
                }
            }
            emit(polygon, &mut output);
        }
        (output.len() <= 8192).then_some(output)
    }
}

fn distance(e: [f32; 3], p: [f32; 2]) -> f32 {
    e[0] * p[0] + e[1] * p[1] + e[2]
}
fn cut(input: &[Vertex], edge: [f32; 3], limit: f32, inside: bool) -> Vec<Vertex> {
    if input.is_empty() {
        return Vec::new();
    }
    let mut output = Vec::new();
    let mut previous = *input.last().unwrap();
    let signed = |v: Vertex| {
        let d = distance(edge, v.position) - limit;
        if inside { d } else { -d }
    };
    let mut pd = signed(previous);
    for current in input.iter().copied() {
        let cd = signed(current);
        if (pd >= 0.0) != (cd >= 0.0) {
            output.push(previous.mix(current, (pd / (pd - cd)).clamp(0.0, 1.0)));
        }
        if cd >= 0.0 {
            output.push(current);
        }
        previous = current;
        pd = cd;
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;
    fn vertex(x: f32, y: f32) -> Vertex {
        Vertex {
            position: [x, y],
            uv: [x / 10.0, y / 10.0],
            color: [0.4, 0.2, 0.1, 0.5],
        }
    }
    #[test]
    fn interior_does_not_fade_and_edge_coverage_is_premultiplied() {
        let clip = Clip::new(&[(0., 0.), (10., 0.), (10., 10.), (0., 10.)]).unwrap();
        let triangle = [vertex(1., 1.), vertex(9., 1.), vertex(5., 9.)];
        let output = clip.triangle(triangle, 0.5).unwrap();
        assert_eq!(output.len(), 1);
        assert_eq!(output[0][0].color, triangle[0].color);
        let edge = clip
            .triangle([vertex(-1., 2.), vertex(2., 2.), vertex(2., 8.)], 0.5)
            .unwrap();
        assert!(edge.iter().any(|t| {
            let alpha = t.iter().map(|v| v.color[3]).sum::<f32>() / 3.0;
            alpha > 0.0 && alpha < 0.5
        }));
        for v in edge.iter().flatten() {
            assert!(v.position[0] >= -0.50001);
            assert!((v.color[0] - v.color[3] * 0.8).abs() < 0.00001);
            assert!((v.uv[0] - v.position[0] / 10.0).abs() < 0.00001);
        }
    }
    #[test]
    fn winding_and_invalid_inputs_are_handled() {
        let a = Clip::new(&[(0., 0.), (10., 0.), (10., 10.), (0., 10.)]).unwrap();
        let b = Clip::new(&[(0., 10.), (10., 10.), (10., 0.), (0., 0.)]).unwrap();
        for x in [-1., 0., 1., 5., 9., 10., 11.] {
            assert_eq!(
                a.contains_interior([x, 5.], 0.5),
                b.contains_interior([x, 5.], 0.5)
            );
        }
        assert!(Clip::new(&[(0., 0.), (f32::NAN, 1.), (1., 0.)]).is_none());
        assert!(Clip::new(&[(0., 0.), (0., 0.), (0., 0.)]).is_none());
    }
}

#[cfg(test)]
mod regression_tests {
    use super::*;
    use crate::continuous_corner::{RoundedRect, polygon_segments};
    #[test]
    fn fractional_dpi_and_small_corners_keep_geometry_bounded() {
        for scale in [0.75f32, 1., 1.25, 1.5, 2., 4.] {
            for radius in [0., 0.25, 4., 26.5, 200.] {
                let shape = RoundedRect::new(
                    [0., 0., 600. * scale, 400. * scale],
                    [radius * scale, 0., radius * 0.5 * scale, radius * scale],
                );
                let mut points = Vec::new();
                shape.for_each_point(polygon_segments(shape.max_radius()), |p| points.push(p));
                let clip = Clip::new(&points).unwrap();
                let v = |x, y| Vertex {
                    position: [x, y],
                    uv: [x / (600. * scale), y / (400. * scale)],
                    color: [0.4, 0.2, 0.1, 0.5],
                };
                let triangles = clip
                    .triangle(
                        [
                            v(-10., -10.),
                            v(1500. * scale, -10.),
                            v(-10., 1000. * scale),
                        ],
                        0.5,
                    )
                    .unwrap();
                assert!(
                    triangles.len() < 4096,
                    "radius={radius}, scale={scale}, triangles={}",
                    triangles.len()
                );
                assert!(clip.storage_bytes() < 1024 * 1024);
                assert!(triangles.iter().flatten().all(|v| {
                    v.position
                        .iter()
                        .chain(v.uv.iter())
                        .chain(v.color.iter())
                        .all(|v| v.is_finite())
                }));
                for t in &triangles {
                    for v in t {
                        assert!((v.color[0] - v.color[3] * 0.8).abs() < 0.0001);
                    }
                }
            }
        }
    }
}
