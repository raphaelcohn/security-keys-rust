// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


use likely::unlikely;
use std::error;
use std::fmt;
use std::fmt::Debug;
use std::fmt::Display;
use std::fmt::Formatter;
use std::ops::Bound;
use std::ops::Range;
use std::ops::RangeBounds;
use serde::Deserialize;
use serde::Serialize;
use crate::descriptors::DescriptorType;
use crate::descriptors::descriptor_index;
use crate::descriptors::DescriptorParser;
use crate::descriptors::verify_remaining_bytes;
use crate::string::GetLocalizedStringError;
use crate::string::LocalizedStrings;
use crate::device::DeadOrAlive;
use crate::device::DeadOrAlive::Alive;
use crate::device::DeadOrAlive::Dead;
use crate::device::DeviceConnection;
use crate::interface::InterfaceNumber;
use crate::interface::MaximumNumberOfInterfaces;
use crate::collections::Bytes;
use std::iter::TrustedLen;
use std::iter::FusedIterator;
use crate::class_and_protocol::FunctionClass;
use crate::class_and_protocol::FunctionClassParseError;
use std::cmp::Ordering;
use crate::configuration::ConfigurationExtraDescriptorParser;


include!("AssociatedInterfaces.rs");
include!("InterfaceAssociationConfigurationExtraDescriptor.rs");
include!("InterfaceAssociationConfigurationExtraDescriptorParseError.rs");
include!("InterfaceAssociationConfigurationExtraDescriptorParser.rs");
