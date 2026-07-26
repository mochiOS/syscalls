#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Ipv4Config {
    pub address: [u8; 4],
    pub subnet_mask: [u8; 4],
    pub gateway: [u8; 4],
    pub dns: [u8; 4],
}
pub fn next_hop(config: Ipv4Config, destination: [u8; 4]) -> Option<[u8; 4]> {
    if config.subnet_mask == [0; 4] || config.address == [0; 4] {
        return None;
    }
    let local = u32::from_be_bytes(config.address);
    let dest = u32::from_be_bytes(destination);
    let mask = u32::from_be_bytes(config.subnet_mask);
    if local & mask == dest & mask {
        Some(destination)
    } else if config.gateway != [0; 4] {
        Some(config.gateway)
    } else {
        None
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn subnet_and_default() {
        let c = Ipv4Config {
            address: [10, 0, 2, 15],
            subnet_mask: [255, 255, 255, 0],
            gateway: [10, 0, 2, 2],
            dns: [10, 0, 2, 3],
        };
        assert_eq!(next_hop(c, [10, 0, 2, 9]), Some([10, 0, 2, 9]));
        assert_eq!(next_hop(c, [8, 8, 8, 8]), Some([10, 0, 2, 2]));
        assert_eq!(
            next_hop(
                Ipv4Config {
                    subnet_mask: [0; 4],
                    ..c
                },
                [8, 8, 8, 8]
            ),
            None
        )
    }
}
