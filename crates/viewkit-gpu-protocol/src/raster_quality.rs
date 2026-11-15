//! Backend-independent raster conventions. Vertex colors and texture bytes use
//! premultiplied alpha in encoded UNORM space. The display path currently does
//! not perform ICC/HDR management or linear-light blending. Changing that
//! requires converting both textures and vertex colors at every backend.

/// Compact smooth falloff with zero derivatives at the centre and outer edge.
/// `distance` is normalized to the shadow's existing blur extent.
pub fn shadow_falloff(distance: f32) -> f32 {
    if !distance.is_finite() {
        return 0.0;
    }
    let t = distance.clamp(0.0, 1.0);
    1.0 - t * t * (3.0 - 2.0 * t)
}
/// Source alpha needed to reach a desired cumulative opacity under source-over.
/// Using the actual quantized accumulated alpha prevents drift over many layers.
pub fn incremental_alpha(target: u8, accumulated: u8) -> u8 {
    if target <= accumulated || accumulated == 255 {
        return 0;
    }
    (((target - accumulated) as u32 * 255 + (255 - accumulated) as u32 / 2)
        / (255 - accumulated) as u32)
        .min(255) as u8
}
/// Encoded-UNORM source-over for premultiplied RGBA8, with an extra coverage mask.
/// Coverage scales RGB and alpha together; transparent texels cannot darken edges.
pub fn source_over(target: [u8; 4], source: [u8; 4], coverage: u8) -> [u8; 4] {
    let scale = |c: u8| (c as u32 * coverage as u32 + 127) / 255;
    let alpha = scale(source[3]);
    let inverse = 255 - alpha;
    core::array::from_fn(|i| {
        (scale(source[i]) + (target[i] as u32 * inverse + 127) / 255).min(255) as u8
    })
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn coverage_and_source_over_keep_premultiplied_channels_consistent() {
        assert_eq!(
            source_over([255; 4], [0, 0, 0, 128], 255),
            [127, 127, 127, 255]
        );
        assert_eq!(
            source_over([0; 4], [128, 64, 32, 128], 128),
            [64, 32, 16, 64]
        );
        assert_eq!(
            source_over([20, 30, 40, 255], [0; 4], 255),
            [20, 30, 40, 255]
        );
    }
    #[test]
    fn shadow_profile_is_monotone_and_layers_reach_the_requested_opacity() {
        assert_eq!(shadow_falloff(0.), 1.);
        assert_eq!(shadow_falloff(1.), 0.);
        let mut previous = 1.;
        for i in 0..=100 {
            let v = shadow_falloff(i as f32 / 100.);
            assert!(v <= previous);
            previous = v;
        }
        assert!(1. - shadow_falloff(0.001) < 0.00001);
        for peak in [5u8, 10, 20, 32, 128] {
            let mut actual = 0u8;
            for i in (0..32).rev() {
                let target = (peak as f32 * shadow_falloff(i as f32 / 32.) + 0.5) as u8;
                let alpha = incremental_alpha(target, actual);
                actual = source_over([0, 0, 0, actual], [0, 0, 0, alpha], 255)[3];
                assert!(actual.abs_diff(target) <= 1);
            }
            assert!(actual.abs_diff(peak) <= 1);
        }
    }
}
