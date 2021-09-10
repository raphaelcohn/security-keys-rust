// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


use super::TerminalEntity;
use likely::unlikely;
use serde::Deserialize;
use serde::Serialize;
use std::error;
use std::fmt;
use std::fmt::Debug;
use std::fmt::Display;
use std::fmt::Formatter;
use crate::serde::TryReserveErrorRemote;
use crate::version::Version;
use crate::interface::video::control::entities::{Entity, DescriptorEntityMinimumLength};
use crate::interface::video::control::entities::entity_index;
use crate::interface::video::control::entity_identifiers::EntityIdentifier;
use crate::interface::video::control::entity_identifiers::TerminalEntityIdentifier;
use crate::device::DeviceConnection;
use crate::device::DeadOrAlive;
use crate::collections::{Bytes, VecExt};
use crate::interface::video::control::entities::terminal::types::CommonTerminalType;
use crate::interface::video::control::entities::terminal::types::UsbTerminalType;
use crate::interface::video::control::entities::terminal::types::UsbTerminalTypeDiscriminants;
use crate::interface::video::control::entities::terminal::types::MediaTransportParseError;
use crate::interface::video::control::entities::terminal::types::ExternalTerminalType;
use crate::interface::video::control::entities::terminal::types::ExternalTerminalTypeDiscriminants;
use crate::interface::video::control::entities::terminal::types::InputSpecificTerminalType;
use crate::interface::video::control::entities::terminal::types::OutputSpecificTerminalTypeDiscriminants;
use swiss_army_knife::get_unchecked::GetUnchecked;
use std::collections::TryReserveError;
use crate::device::DeadOrAlive::Alive;
use crate::string::{LocalizedStrings, GetLocalizedStringError};
use crate::interface::video::control::entities::terminal::types::camera::CameraParseError;


include!("InputTerminalEntity.rs");
include!("InputTerminalEntityParseError.rs");
include!("InputTerminalType.rs");
