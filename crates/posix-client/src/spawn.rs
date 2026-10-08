pub const RESET_IDS: i16 = 0x01;
pub const SET_PROCESS_GROUP: i16 = 0x02;
pub const SET_SCHEDULING_PARAMETERS: i16 = 0x04;
pub const SET_SCHEDULER: i16 = 0x08;
pub const SET_SIGNAL_DEFAULTS: i16 = 0x10;
pub const SET_SIGNAL_MASK: i16 = 0x20;

pub const KNOWN_ATTRIBUTE_FLAGS: i16 = RESET_IDS
    | SET_PROCESS_GROUP
    | SET_SCHEDULING_PARAMETERS
    | SET_SCHEDULER
    | SET_SIGNAL_DEFAULTS
    | SET_SIGNAL_MASK;

pub const IMPLEMENTED_ATTRIBUTE_FLAGS: i16 =
    RESET_IDS | SET_PROCESS_GROUP | SET_SIGNAL_DEFAULTS | SET_SIGNAL_MASK;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AttributeFlags {
    Supported,
    RequiresScheduler,
    Invalid,
}

pub const fn classify_attribute_flags(flags: i16) -> AttributeFlags {
    if flags & !KNOWN_ATTRIBUTE_FLAGS != 0 {
        AttributeFlags::Invalid
    } else if flags & !IMPLEMENTED_ATTRIBUTE_FLAGS != 0 {
        AttributeFlags::RequiresScheduler
    } else {
        AttributeFlags::Supported
    }
}
