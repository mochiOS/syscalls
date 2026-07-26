#![no_std]

mod codec;
mod command;
mod response;
mod types;

pub use command::{
    AttachBacking, AttachBackingView, COMMAND_HEADER_LEN, Command, ContextCreate,
    ContextCreateView, ContextResource, CursorPosition, CursorUpdate, DecodedCommand, GetCapset,
    ResourceCreate2d, ResourceCreate3d, ResourceOperation, SetScanout, Submit3d, Submit3dView,
    TransferHost3d, TransferToHost2d,
};
pub use response::{
    CAPSET_INFO_LEN, CapsetInfo, DISPLAY_INFO_LEN, DISPLAY_MODE_COUNT, DisplayInfo,
    DisplayInfoView, Response, ResponseError, ResponseMessage,
};
pub use types::{
    Box3d, DecodeError, EncodeError, MemoryEntry, PixelFormat, Rect,
    VIRTIO_GPU_FORMAT_B8G8R8A8_UNORM, VIRTIO_GPU_FORMAT_B8G8R8X8_UNORM,
};

pub const VIRTIO_GPU_F_VIRGL: u64 = 1 << 0;
pub const CAPSET_VIRGL: u32 = 1;
pub const CAPSET_VIRGL2: u32 = 2;

pub const TYPE_GET_DISPLAY_INFO: u32 = 0x0100;
pub const TYPE_RESOURCE_CREATE_2D: u32 = 0x0101;
pub const TYPE_RESOURCE_UNREF: u32 = 0x0102;
pub const TYPE_SET_SCANOUT: u32 = 0x0103;
pub const TYPE_RESOURCE_FLUSH: u32 = 0x0104;
pub const TYPE_TRANSFER_TO_HOST_2D: u32 = 0x0105;
pub const TYPE_RESOURCE_ATTACH_BACKING: u32 = 0x0106;
pub const TYPE_RESOURCE_DETACH_BACKING: u32 = 0x0107;
pub const TYPE_GET_CAPSET_INFO: u32 = 0x0108;
pub const TYPE_GET_CAPSET: u32 = 0x0109;

pub const TYPE_CTX_CREATE: u32 = 0x0200;
pub const TYPE_CTX_DESTROY: u32 = 0x0201;
pub const TYPE_CTX_ATTACH_RESOURCE: u32 = 0x0202;
pub const TYPE_CTX_DETACH_RESOURCE: u32 = 0x0203;
pub const TYPE_RESOURCE_CREATE_3D: u32 = 0x0204;
pub const TYPE_TRANSFER_TO_HOST_3D: u32 = 0x0205;
pub const TYPE_TRANSFER_FROM_HOST_3D: u32 = 0x0206;
pub const TYPE_SUBMIT_3D: u32 = 0x0207;
pub const TYPE_UPDATE_CURSOR: u32 = 0x0300;
pub const TYPE_MOVE_CURSOR: u32 = 0x0301;

pub const TYPE_RESP_OK_NODATA: u32 = 0x1100;
pub const TYPE_RESP_OK_DISPLAY_INFO: u32 = 0x1101;
pub const TYPE_RESP_OK_CAPSET_INFO: u32 = 0x1102;
pub const TYPE_RESP_OK_CAPSET: u32 = 0x1103;
pub const TYPE_RESP_ERR_UNSPEC: u32 = 0x1200;
pub const TYPE_RESP_ERR_OUT_OF_MEMORY: u32 = 0x1201;
pub const TYPE_RESP_ERR_INVALID_SCANOUT_ID: u32 = 0x1202;
pub const TYPE_RESP_ERR_INVALID_RESOURCE_ID: u32 = 0x1203;
pub const TYPE_RESP_ERR_INVALID_CONTEXT_ID: u32 = 0x1204;
pub const TYPE_RESP_ERR_INVALID_PARAMETER: u32 = 0x1205;
