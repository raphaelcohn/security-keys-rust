// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


use enumflags2::bitflags;
use likely::likely;
use likely::unlikely;
use serde::Deserialize;
use serde::Serialize;
use std::error;
use std::fmt;
use std::fmt::Debug;
use std::fmt::Display;
use std::fmt::Formatter;
use std::mem::size_of;
use strum_macros::EnumDiscriminants;
use crate::version::Version;
use crate::interface::video::control::entities::terminal::input::InputTerminalEntityParseError;
use crate::interface::video::control::entities::terminal::output::OutputTerminalEntityParseError;
use crate::collections::Bytes;
use crate::collections::WrappedBitFlags;
use crate::interface::video::control::entities::entity_index_non_constant;
use swiss_army_knife::get_unchecked::GetUnchecked;
use crate::interface::video::control::entities::terminal::types::camera::Camera;


/// Camera.
pub mod camera;


include!("CommonTerminalType.rs");
include!("ExternalTerminalType.rs");
include!("InputSpecificTerminalType.rs");
include!("MediaTransport.rs");
include!("MediaTransportMode.rs");
include!("MediaTransportParseError.rs");
include!("OutputSpecificTerminalType.rs");
include!("UsbTerminalType.rs");
