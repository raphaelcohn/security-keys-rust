// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


use crate::{VecExt, Bytes};
use super::control_transfers::descriptors::MinimumStandardUsbDescriptorLength;
use likely::likely;
use likely::unlikely;
use serde::Deserialize;
use serde::Serialize;
use std::collections::TryReserveError;
use std::error;
use std::fmt;
use std::fmt::Debug;
use std::fmt::Display;
use std::fmt::Formatter;
use std::slice::from_raw_parts;
use swiss_army_knife::get_unchecked::GetUnchecked;
use crate::string::StringFinder;
use crate::device::DeadOrAlive;
use crate::device::DeadOrAlive::{Alive, Dead};


include!("AdditionalDescriptor.rs");
include!("AdditionalDescriptorParseError.rs");
include!("AdditionalDescriptorParser.rs");
include!("DescriptorHeaderLength.rs");
include!("DescriptorType.rs");
include!("extra_to_slice.rs");
include!("parse_additional_descriptors.rs");
include!("reduce_b_length_to_descriptor_body_length.rs");
include!("verify_remaining_bytes.rs");
