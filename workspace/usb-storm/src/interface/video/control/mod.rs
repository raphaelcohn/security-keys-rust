// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


use super::CS_INTERFACE;
use self::entities::EntityDescriptorParseError;
use crate::class_and_protocol::VideoProtocol;
use crate::collections::Bytes;
use crate::collections::VecExt;
use crate::collections::WithCapacity;
use crate::collections::WrappedIndexSet;
use crate::descriptors::DescriptorHeaderLength;
use crate::descriptors::DescriptorParser;
use crate::descriptors::DescriptorSubType;
use crate::descriptors::DescriptorType;
use crate::descriptors::descriptor_index;
use crate::descriptors::descriptor_index_non_constant;
use crate::descriptors::verify_remaining_bytes;
use crate::device::DeadOrAlive::Alive;
use crate::device::DeadOrAlive;
use crate::device::DeviceConnection;
use crate::interface::InterfaceNumber;
use crate::interface::MaximumNumberOfInterfaces;
use crate::serde::TryReserveErrorRemote;
use crate::version::Version;
use crate::version::VersionParseError;
use likely::unlikely;
use serde::Deserialize;
use serde::Serialize;
use std::collections::TryReserveError;
use std::error;
use std::fmt::Debug;
use std::fmt::Display;
use std::fmt::Formatter;
use std::fmt;
use std::mem::size_of;
use swiss_army_knife::get_unchecked::GetUnchecked;
use crate::interface::video::control::entities::EntityDescriptors;


/// Entities.
pub mod entities;


/// Entity identifiers.
pub mod entity_identifiers;


include!("HeaderInterfacesCollectionParseError.rs");
include!("UndefinedVideoControlInterfaceExtraDescriptorParseError.rs");
include!("VC_.rs");
include!("VideoControl.rs");
include!("VideoControlInterfaceExtraDescriptor.rs");
include!("VideoControlInterfaceExtraDescriptorParseError.rs");
include!("VideoControlInterfaceExtraDescriptorParser.rs");
include!("VideoControlParseError.rs");
