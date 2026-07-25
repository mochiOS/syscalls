use mochios_virtio_gpu_protocol::*;

fn encode<const N: usize>(command: Command<'_>) -> [u8; N] {
    let mut buffer = [0u8; N];
    match command.encode(&mut buffer) {
        Ok(length) => assert_eq!(length, N),
        Err(error) => panic!("encode failed: {error:?}"),
    }
    buffer
}

fn rect() -> Rect {
    Rect {
        x: 1,
        y: 2,
        width: 3,
        height: 4,
    }
}

#[test]
fn command_types_and_lengths_match_specification() {
    assert_eq!(TYPE_GET_DISPLAY_INFO, 0x0100);
    assert_eq!(TYPE_RESOURCE_CREATE_2D, 0x0101);
    assert_eq!(TYPE_RESOURCE_UNREF, 0x0102);
    assert_eq!(TYPE_SET_SCANOUT, 0x0103);
    assert_eq!(TYPE_RESOURCE_FLUSH, 0x0104);
    assert_eq!(TYPE_TRANSFER_TO_HOST_2D, 0x0105);
    assert_eq!(TYPE_RESOURCE_ATTACH_BACKING, 0x0106);
    assert_eq!(TYPE_RESOURCE_DETACH_BACKING, 0x0107);
    assert_eq!(COMMAND_HEADER_LEN, 24);
    assert_eq!(DISPLAY_INFO_LEN, 408);
}

#[test]
fn all_commands_have_golden_little_endian_encodings() {
    let get = encode::<24>(Command::GetDisplayInfo);
    assert_eq!(
        get,
        [
            0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ]
    );

    let create = encode::<40>(Command::ResourceCreate2d(ResourceCreate2d {
        resource_id: 7,
        format: PixelFormat::B8G8R8X8_UNORM,
        width: 640,
        height: 480,
    }));
    assert_eq!(&create[0..4], &[1, 1, 0, 0]);
    assert_eq!(
        &create[24..40],
        &[7, 0, 0, 0, 2, 0, 0, 0, 128, 2, 0, 0, 224, 1, 0, 0]
    );

    let unref = encode::<32>(Command::ResourceUnref(ResourceOperation { resource_id: 7 }));
    assert_eq!(&unref[0..4], &[2, 1, 0, 0]);
    assert_eq!(&unref[24..32], &[7, 0, 0, 0, 0, 0, 0, 0]);

    let scanout = encode::<48>(Command::SetScanout(SetScanout {
        rect: rect(),
        scanout_id: 5,
        resource_id: 7,
    }));
    assert_eq!(&scanout[0..4], &[3, 1, 0, 0]);
    assert_eq!(
        &scanout[24..48],
        &[
            1, 0, 0, 0, 2, 0, 0, 0, 3, 0, 0, 0, 4, 0, 0, 0, 5, 0, 0, 0, 7, 0, 0, 0
        ]
    );

    let flush = encode::<48>(Command::ResourceFlush {
        rect: rect(),
        resource_id: 7,
    });
    assert_eq!(&flush[0..4], &[4, 1, 0, 0]);
    assert_eq!(&flush[40..48], &[7, 0, 0, 0, 0, 0, 0, 0]);

    let transfer = encode::<56>(Command::TransferToHost2d(TransferToHost2d {
        rect: rect(),
        offset: 0x0807_0605_0403_0201,
        resource_id: 7,
    }));
    assert_eq!(&transfer[0..4], &[5, 1, 0, 0]);
    assert_eq!(
        &transfer[40..56],
        &[1, 2, 3, 4, 5, 6, 7, 8, 7, 0, 0, 0, 0, 0, 0, 0]
    );

    let entries = [MemoryEntry {
        address: 0x0807_0605_0403_0201,
        length: 0x0c0b_0a09,
    }];
    let attach = encode::<48>(Command::ResourceAttachBacking(AttachBacking {
        resource_id: 7,
        entries: &entries,
    }));
    assert_eq!(&attach[0..4], &[6, 1, 0, 0]);
    assert_eq!(
        &attach[24..48],
        &[
            7, 0, 0, 0, 1, 0, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 0, 0, 0, 0
        ]
    );

    let detach = encode::<32>(Command::ResourceDetachBacking(ResourceOperation {
        resource_id: 7,
    }));
    assert_eq!(&detach[0..4], &[7, 1, 0, 0]);
    assert_eq!(&detach[24..32], &[7, 0, 0, 0, 0, 0, 0, 0]);
}

#[test]
fn all_commands_decode_round_trip() {
    let commands = [
        encode::<24>(Command::GetDisplayInfo).to_vec(),
        encode::<40>(Command::ResourceCreate2d(ResourceCreate2d {
            resource_id: 1,
            format: PixelFormat::B8G8R8X8_UNORM,
            width: 2,
            height: 3,
        }))
        .to_vec(),
        encode::<32>(Command::ResourceUnref(ResourceOperation { resource_id: 1 })).to_vec(),
        encode::<48>(Command::SetScanout(SetScanout {
            rect: rect(),
            scanout_id: 0,
            resource_id: 1,
        }))
        .to_vec(),
        encode::<48>(Command::ResourceFlush {
            rect: rect(),
            resource_id: 1,
        })
        .to_vec(),
        encode::<56>(Command::TransferToHost2d(TransferToHost2d {
            rect: rect(),
            offset: 0,
            resource_id: 1,
        }))
        .to_vec(),
        encode::<32>(Command::ResourceDetachBacking(ResourceOperation {
            resource_id: 1,
        }))
        .to_vec(),
    ];
    for command in &commands {
        assert!(DecodedCommand::decode(command).is_ok());
    }
    let entries = [MemoryEntry {
        address: 0x1000,
        length: 4096,
    }];
    let attach = encode::<48>(Command::ResourceAttachBacking(AttachBacking {
        resource_id: 1,
        entries: &entries,
    }));
    match DecodedCommand::decode(&attach) {
        Ok(DecodedCommand::ResourceAttachBacking(view)) => {
            assert_eq!(view.resource_id(), 1);
            assert_eq!(view.entry_count(), 1);
            assert_eq!(view.entry(0), Ok(Some(entries[0])));
        }
        result => panic!("unexpected attach decode: {result:?}"),
    }
}

#[test]
fn rejects_short_excess_unknown_and_reserved_commands() {
    assert_eq!(
        DecodedCommand::decode(&[0; 23]),
        Err(DecodeError::InvalidLength {
            expected: 24,
            actual: 23,
        })
    );
    let mut excess = [0u8; 25];
    excess[1] = 1;
    assert_eq!(
        DecodedCommand::decode(&excess),
        Err(DecodeError::InvalidLength {
            expected: 24,
            actual: 25,
        })
    );
    let mut unknown = [0u8; 24];
    unknown[0..4].copy_from_slice(&0xdead_beefu32.to_le_bytes());
    assert_eq!(
        DecodedCommand::decode(&unknown),
        Err(DecodeError::UnknownCommand {
            actual: 0xdead_beef
        })
    );
    let mut reserved = encode::<24>(Command::GetDisplayInfo);
    reserved[4] = 1;
    assert_eq!(
        DecodedCommand::decode(&reserved),
        Err(DecodeError::NonZeroReserved {
            offset: 4,
            actual: 1,
        })
    );
}

#[test]
fn rejects_invalid_backing_and_encode_buffer() {
    let entries = [MemoryEntry {
        address: u64::MAX,
        length: 2,
    }];
    let mut buffer = [0u8; 48];
    assert_eq!(
        Command::ResourceAttachBacking(AttachBacking {
            resource_id: 1,
            entries: &entries,
        })
        .encode(&mut buffer),
        Err(EncodeError::InvalidValue)
    );
    let mut short = [0u8; 23];
    assert_eq!(
        Command::GetDisplayInfo.encode(&mut short),
        Err(EncodeError::BufferTooSmall {
            required: 24,
            actual: 23,
        })
    );
}

#[test]
fn response_round_trip_golden_and_validation() {
    let mut no_data = [0u8; 24];
    assert_eq!(
        ResponseMessage::NoData.encode(&mut no_data),
        Ok(no_data.len())
    );
    assert_eq!(&no_data[0..4], &[0, 17, 0, 0]);
    assert!(matches!(Response::decode(&no_data), Ok(Response::NoData)));

    let mut modes = [DisplayInfo::default(); DISPLAY_MODE_COUNT];
    modes[0] = DisplayInfo {
        rect: Rect {
            x: 0,
            y: 0,
            width: 1280,
            height: 800,
        },
        enabled: true,
    };
    let mut display = [0u8; DISPLAY_INFO_LEN];
    assert_eq!(
        ResponseMessage::DisplayInfo(&modes).encode(&mut display),
        Ok(DISPLAY_INFO_LEN)
    );
    assert_eq!(&display[0..4], &[1, 17, 0, 0]);
    assert_eq!(
        &display[24..48],
        &[
            0, 0, 0, 0, 0, 0, 0, 0, 0, 5, 0, 0, 32, 3, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0
        ]
    );
    match Response::decode(&display) {
        Ok(Response::DisplayInfo(view)) => assert_eq!(view.mode(0), Ok(Some(modes[0]))),
        result => panic!("unexpected display response: {result:?}"),
    }

    let mut error = [0u8; 24];
    assert_eq!(
        ResponseMessage::Error(ResponseError::InvalidParameter).encode(&mut error),
        Ok(24)
    );
    assert!(matches!(
        Response::decode(&error),
        Ok(Response::Error(ResponseError::InvalidParameter))
    ));

    let mut unknown = [0u8; 24];
    unknown[0..4].copy_from_slice(&0x9999u32.to_le_bytes());
    assert_eq!(
        Response::decode(&unknown),
        Err(DecodeError::UnknownResponse { actual: 0x9999 })
    );
    let mut reserved = no_data;
    reserved[20] = 1;
    assert_eq!(
        Response::decode(&reserved),
        Err(DecodeError::NonZeroReserved {
            offset: 20,
            actual: 1,
        })
    );
}

#[test]
fn rejects_response_length_mismatch() {
    let mut no_data = [0u8; 24];
    assert!(ResponseMessage::NoData.encode(&mut no_data).is_ok());
    let mut excess = [0u8; 25];
    excess[..24].copy_from_slice(&no_data);
    assert_eq!(
        Response::decode(&excess),
        Err(DecodeError::InvalidLength {
            expected: 24,
            actual: 25,
        })
    );
}
