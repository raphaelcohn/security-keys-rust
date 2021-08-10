// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


use self::entities::Version3EntityDescriptors;
use crate::{Bytes, VecExt};
use crate::additional_descriptors::AdditionalDescriptorParser;
use crate::additional_descriptors::DescriptorType;
use crate::additional_descriptors::DescriptorHeaderLength;
use crate::additional_descriptors::verify_remaining_bytes;
use crate::integers::u2;
use likely::unlikely;
use serde::Deserialize;
use serde::Serialize;
use std::error;
use std::fmt;
use std::fmt::Debug;
use std::fmt::Display;
use std::fmt::Formatter;
use swiss_army_knife::get_unchecked::GetUnchecked;
use crate::class_and_protocol::AudioProtocol;
use indexmap::set::IndexSet;
use crate::interface::{InterfaceNumber, MaximumNumberOfInterfaces};
use crate::version::Version;
use crate::version::VersionParseError;
use self::entities::EntityDescriptorParseError;
use std::collections::TryReserveError;
use std::mem::size_of;


/// Entities.
pub mod entities;


include!("AudioControlInterfaceAdditionalDescriptor.rs");
include!("AudioControlInterfaceAdditionalDescriptorParseError.rs");
include!("AudioControlInterfaceAdditionalDescriptorParser.rs");
include!("AudioFunctionCategory.rs");
