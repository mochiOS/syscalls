#![no_std]

mod codec;
mod command;
mod response;
mod types;

pub use command::{
    AttachBacking, AttachBackingView, COMMAND_HEADER_LEN, Command, DecodedCommand,
    ResourceCreate2d, ResourceOperation, SetScanout, TransferToHost2d,
};
pub use response::{
    DISPLAY_INFO_LEN, DISPLAY_MODE_COUNT, DisplayInfo, DisplayInfoView, Response, ResponseError,
    ResponseMessage,
};
pub use types::{
    DecodeError, EncodeError, MemoryEntry, PixelFormat, Rect, VIRTIO_GPU_FORMAT_B8G8R8X8_UNORM,
};

pub const TYPE_GET_DISPLAY_INFO: u32 = 0x0100;
pub const TYPE_RESOURCE_CREATE_2D: u32 = 0x0101;
pub const TYPE_RESOURCE_UNREF: u32 = 0x0102;
pub const TYPE_SET_SCANOUT: u32 = 0x0103;
pub const TYPE_RESOURCE_FLUSH: u32 = 0x0104;
pub const TYPE_TRANSFER_TO_HOST_2D: u32 = 0x0105;
pub const TYPE_RESOURCE_ATTACH_BACKING: u32 = 0x0106;
pub const TYPE_RESOURCE_DETACH_BACKING: u32 = 0x0107;

pub const TYPE_RESP_OK_NODATA: u32 = 0x1100;
pub const TYPE_RESP_OK_DISPLAY_INFO: u32 = 0x1101;
pub const TYPE_RESP_ERR_UNSPEC: u32 = 0x1200;
pub const TYPE_RESP_ERR_OUT_OF_MEMORY: u32 = 0x1201;
pub const TYPE_RESP_ERR_INVALID_SCANOUT_ID: u32 = 0x1202;
pub const TYPE_RESP_ERR_INVALID_RESOURCE_ID: u32 = 0x1203;
pub const TYPE_RESP_ERR_INVALID_CONTEXT_ID: u32 = 0x1204;
pub const TYPE_RESP_ERR_INVALID_PARAMETER: u32 = 0x1205;
