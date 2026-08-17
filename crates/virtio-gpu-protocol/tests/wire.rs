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
    assert_eq!(TYPE_GET_CAPSET_INFO, 0x0108);
    assert_eq!(TYPE_GET_CAPSET, 0x0109);
    assert_eq!(TYPE_CTX_CREATE, 0x0200);
    assert_eq!(TYPE_CTX_DESTROY, 0x0201);
    assert_eq!(TYPE_CTX_ATTACH_RESOURCE, 0x0202);
    assert_eq!(TYPE_CTX_DETACH_RESOURCE, 0x0203);
    assert_eq!(TYPE_RESOURCE_CREATE_3D, 0x0204);
    assert_eq!(TYPE_TRANSFER_TO_HOST_3D, 0x0205);
    assert_eq!(TYPE_TRANSFER_FROM_HOST_3D, 0x0206);
    assert_eq!(TYPE_SUBMIT_3D, 0x0207);
    assert_eq!(TYPE_UPDATE_CURSOR, 0x0300);
    assert_eq!(TYPE_MOVE_CURSOR, 0x0301);
    assert_eq!(VIRTIO_GPU_F_VIRGL, 1);
    assert_eq!(COMMAND_HEADER_LEN, 24);
    assert_eq!(DISPLAY_INFO_LEN, 408);
}

#[test]
fn fenced_commands_and_responses_preserve_fence_context() {
    let command = Command::ContextDetachResource(ContextResource {
        context_id: 9,
        resource_id: 7,
    });
    assert_eq!(command.context_id(), 9);
    let mut encoded = [0u8; 32];
    assert_eq!(command.encode_fenced(&mut encoded, u64::MAX), Ok(32));
    assert_eq!(&encoded[4..8], &1u32.to_le_bytes());
    assert_eq!(&encoded[8..16], &u64::MAX.to_le_bytes());
    assert_eq!(&encoded[16..20], &9u32.to_le_bytes());
    assert_eq!(
        command.encode_fenced(&mut encoded, 0),
        Err(EncodeError::InvalidValue)
    );

    let mut response = [0u8; 24];
    assert_eq!(ResponseMessage::NoData.encode(&mut response), Ok(24));
    response[4..8].copy_from_slice(&1u32.to_le_bytes());
    response[8..16].copy_from_slice(&u64::MAX.to_le_bytes());
    response[16..20].copy_from_slice(&9u32.to_le_bytes());
    assert!(matches!(
        Response::decode_fenced(&response, u64::MAX, 9),
        Ok(Response::NoData)
    ));
    assert!(matches!(
        Response::decode_fenced(&response, 1, 9),
        Err(DecodeError::InvalidValue { offset: 8, .. })
    ));
    assert!(matches!(
        Response::decode(&response),
        Err(DecodeError::NonZeroReserved { offset: 4, .. })
    ));
}

#[test]
fn cursor_commands_round_trip_and_match_golden_bytes() {
    let position = CursorPosition {
        scanout_id: 3,
        x: 0x1122_3344,
        y: 0x5566_7788,
    };
    let update = encode::<56>(Command::UpdateCursor(CursorUpdate {
        position,
        resource_id: 7,
        hotspot_x: 1,
        hotspot_y: 2,
    }));
    assert_eq!(&update[0..4], &[0, 3, 0, 0]);
    assert_eq!(
        &update[24..56],
        &[
            3, 0, 0, 0, 0x44, 0x33, 0x22, 0x11, 0x88, 0x77, 0x66, 0x55, 0, 0, 0, 0, 7, 0, 0, 0, 1,
            0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0,
        ]
    );
    assert_eq!(
        DecodedCommand::decode(&update),
        Ok(DecodedCommand::UpdateCursor(CursorUpdate {
            position,
            resource_id: 7,
            hotspot_x: 1,
            hotspot_y: 2,
        }))
    );

    let hide = encode::<56>(Command::UpdateCursor(CursorUpdate {
        position,
        resource_id: 0,
        hotspot_x: 0,
        hotspot_y: 0,
    }));
    assert_eq!(
        DecodedCommand::decode(&hide),
        Ok(DecodedCommand::UpdateCursor(CursorUpdate {
            position,
            resource_id: 0,
            hotspot_x: 0,
            hotspot_y: 0,
        }))
    );

    let movement = encode::<56>(Command::MoveCursor(position));
    assert_eq!(&movement[0..4], &[1, 3, 0, 0]);
    assert!(movement[36..].iter().all(|byte| *byte == 0));
    assert_eq!(
        DecodedCommand::decode(&movement),
        Ok(DecodedCommand::MoveCursor(position))
    );
}

#[test]
fn three_d_commands_have_golden_encodings() {
    let create_context = encode::<96>(Command::ContextCreate(ContextCreate {
        context_id: 9,
        context_init: CAPSET_VIRGL,
        debug_name: b"mochi",
    }));
    assert_eq!(&create_context[0..4], &[0, 2, 0, 0]);
    assert_eq!(&create_context[16..20], &[9, 0, 0, 0]);
    assert_eq!(
        &create_context[24..37],
        &[5, 0, 0, 0, 1, 0, 0, 0, b'm', b'o', b'c', b'h', b'i']
    );
    assert!(create_context[37..].iter().all(|byte| *byte == 0));

    let attach = encode::<32>(Command::ContextAttachResource(ContextResource {
        context_id: 9,
        resource_id: 7,
    }));
    assert_eq!(&attach[0..4], &[2, 2, 0, 0]);
    assert_eq!(&attach[16..20], &[9, 0, 0, 0]);
    assert_eq!(&attach[24..32], &[7, 0, 0, 0, 0, 0, 0, 0]);

    let create_resource = encode::<72>(Command::ResourceCreate3d(ResourceCreate3d {
        resource_id: 7,
        target: 2,
        format: 1,
        bind: 3,
        width: 640,
        height: 480,
        depth: 1,
        array_size: 1,
        last_level: 0,
        samples: 0,
        flags: 1,
    }));
    assert_eq!(&create_resource[0..4], &[4, 2, 0, 0]);
    assert_eq!(
        &create_resource[24..40],
        &[7, 0, 0, 0, 2, 0, 0, 0, 1, 0, 0, 0, 3, 0, 0, 0]
    );
    assert_eq!(
        &create_resource[40..56],
        &[128, 2, 0, 0, 224, 1, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0]
    );

    let transfer = encode::<72>(Command::TransferToHost3d(TransferHost3d {
        context_id: 9,
        box_3d: Box3d {
            x: 1,
            y: 2,
            z: 3,
            width: 4,
            height: 5,
            depth: 6,
        },
        offset: 0x0807_0605_0403_0201,
        resource_id: 7,
        level: 8,
        stride: 9,
        layer_stride: 10,
    }));
    assert_eq!(&transfer[0..4], &[5, 2, 0, 0]);
    assert_eq!(&transfer[16..20], &[9, 0, 0, 0]);
    assert_eq!(&transfer[48..56], &[1, 2, 3, 4, 5, 6, 7, 8]);
    assert_eq!(
        &transfer[56..72],
        &[7, 0, 0, 0, 8, 0, 0, 0, 9, 0, 0, 0, 10, 0, 0, 0]
    );

    let submit = encode::<40>(Command::Submit3d(Submit3d {
        context_id: 9,
        commands: &[1, 2, 3, 4, 5, 6, 7, 8],
    }));
    assert_eq!(&submit[0..4], &[7, 2, 0, 0]);
    assert_eq!(&submit[16..20], &[9, 0, 0, 0]);
    assert_eq!(
        &submit[24..40],
        &[8, 0, 0, 0, 0, 0, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8]
    );
}

#[test]
fn three_d_commands_decode_round_trip() {
    let commands = [
        encode::<32>(Command::GetCapsetInfo { index: 1 }).to_vec(),
        encode::<32>(Command::GetCapset(GetCapset {
            capset_id: CAPSET_VIRGL2,
            version: 2,
        }))
        .to_vec(),
        encode::<24>(Command::ContextDestroy { context_id: 9 }).to_vec(),
        encode::<32>(Command::ContextDetachResource(ContextResource {
            context_id: 9,
            resource_id: 7,
        }))
        .to_vec(),
        encode::<72>(Command::TransferFromHost3d(TransferHost3d {
            context_id: 9,
            box_3d: Box3d {
                x: 0,
                y: 0,
                z: 0,
                width: 4,
                height: 4,
                depth: 1,
            },
            offset: 0,
            resource_id: 7,
            level: 0,
            stride: 16,
            layer_stride: 64,
        }))
        .to_vec(),
    ];
    for command in commands {
        assert!(DecodedCommand::decode(&command).is_ok());
    }

    let context = encode::<96>(Command::ContextCreate(ContextCreate {
        context_id: 9,
        context_init: 0,
        debug_name: b"renderer",
    }));
    assert!(matches!(
        DecodedCommand::decode(&context),
        Ok(DecodedCommand::ContextCreate(ContextCreateView {
            context_id: 9,
            context_init: 0,
            debug_name: b"renderer",
        }))
    ));

    let submit = encode::<36>(Command::Submit3d(Submit3d {
        context_id: 9,
        commands: &[1, 2, 3, 4],
    }));
    assert!(matches!(
        DecodedCommand::decode(&submit),
        Ok(DecodedCommand::Submit3d(Submit3dView {
            context_id: 9,
            commands: &[1, 2, 3, 4],
        }))
    ));
}

#[test]
fn three_d_commands_reject_invalid_context_stream_and_reserved_data() {
    let mut buffer = [0u8; 96];
    assert_eq!(
        Command::ContextCreate(ContextCreate {
            context_id: 0,
            context_init: 0,
            debug_name: b"renderer",
        })
        .encode(&mut buffer),
        Err(EncodeError::InvalidValue)
    );
    let mut submit = [0u8; 36];
    assert_eq!(
        Command::Submit3d(Submit3d {
            context_id: 9,
            commands: &[1, 2, 3],
        })
        .encode(&mut submit),
        Err(EncodeError::InvalidValue)
    );
    let mut context = encode::<96>(Command::ContextCreate(ContextCreate {
        context_id: 9,
        context_init: 0,
        debug_name: b"renderer",
    }));
    context[95] = 1;
    assert_eq!(
        DecodedCommand::decode(&context),
        Err(DecodeError::NonZeroReserved {
            offset: 40,
            actual: 1,
        })
    );
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
    let zero_length = [MemoryEntry {
        address: 0x1000,
        length: 0,
    }];
    assert_eq!(
        Command::ResourceAttachBacking(AttachBacking {
            resource_id: 1,
            entries: &zero_length,
        })
        .encode(&mut buffer),
        Err(EncodeError::InvalidValue)
    );
    assert_eq!(
        Command::ResourceAttachBacking(AttachBacking {
            resource_id: 1,
            entries: &[],
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
fn preserves_multiple_non_contiguous_backing_entries() {
    let entries = [
        MemoryEntry {
            address: 0x1000,
            length: 4096,
        },
        MemoryEntry {
            address: 0x9000,
            length: 8192,
        },
    ];
    let attach = encode::<64>(Command::ResourceAttachBacking(AttachBacking {
        resource_id: 3,
        entries: &entries,
    }));
    match DecodedCommand::decode(&attach) {
        Ok(DecodedCommand::ResourceAttachBacking(view)) => {
            assert_eq!(view.entry_count(), entries.len());
            assert_eq!(view.entry(0), Ok(Some(entries[0])));
            assert_eq!(view.entry(1), Ok(Some(entries[1])));
            assert_eq!(view.entry(2), Ok(None));
        }
        result => panic!("unexpected attach decode: {result:?}"),
    }
}

#[test]
fn scanout_zero_resource_is_reserved_for_disable() {
    let disable = encode::<48>(Command::SetScanout(SetScanout {
        rect: Rect::default(),
        scanout_id: 0,
        resource_id: 0,
    }));
    assert!(matches!(
        DecodedCommand::decode(&disable),
        Ok(DecodedCommand::SetScanout(SetScanout {
            rect: Rect {
                x: 0,
                y: 0,
                width: 0,
                height: 0,
            },
            scanout_id: 0,
            resource_id: 0,
        }))
    ));

    let mut invalid = [0u8; 48];
    assert_eq!(
        Command::SetScanout(SetScanout {
            rect: rect(),
            scanout_id: 0,
            resource_id: 0,
        })
        .encode(&mut invalid),
        Err(EncodeError::InvalidValue)
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

#[test]
fn capset_responses_round_trip_and_validate_reserved_data() {
    let info = CapsetInfo {
        id: CAPSET_VIRGL2,
        maximum_version: 2,
        maximum_size: 512,
    };
    let mut encoded_info = [0u8; CAPSET_INFO_LEN];
    assert_eq!(
        ResponseMessage::CapsetInfo(info).encode(&mut encoded_info),
        Ok(CAPSET_INFO_LEN)
    );
    assert_eq!(&encoded_info[0..4], &[2, 17, 0, 0]);
    assert_eq!(
        &encoded_info[24..40],
        &[2, 0, 0, 0, 2, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0]
    );
    assert!(matches!(
        Response::decode(&encoded_info),
        Ok(Response::CapsetInfo(decoded)) if decoded == info
    ));

    let mut capset = [0u8; 28];
    assert_eq!(
        ResponseMessage::Capset(&[1, 2, 3, 4]).encode(&mut capset),
        Ok(28)
    );
    assert_eq!(&capset[0..4], &[3, 17, 0, 0]);
    assert!(matches!(
        Response::decode(&capset),
        Ok(Response::Capset([1, 2, 3, 4]))
    ));

    encoded_info[36] = 1;
    assert_eq!(
        Response::decode(&encoded_info),
        Err(DecodeError::NonZeroReserved {
            offset: 36,
            actual: 1,
        })
    );
}
