// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


use crate::serde::TryReserveErrorRemote;
use crate::interface::audio::Control;
use likely::unlikely;
use std::error;
use std::fmt;
use std::fmt::Debug;
use std::fmt::Display;
use std::fmt::Formatter;
use serde::Deserialize;
use serde::Serialize;
use crate::collections::{Bytes, VecExt};
use crate::descriptors::{descriptor_index, DescriptorSubType, verify_remaining_bytes};
use crate::class_and_protocol::AudioProtocol;
use swiss_army_knife::get_unchecked::GetUnchecked;
use std::collections::TryReserveError;
use crate::device::DeadOrAlive;
use crate::control_transfers::descriptors::MinimumStandardUsbDescriptorLength;
use crate::device::DeadOrAlive::Alive;
use crate::end_point::EndPointExtraDescriptor;


include!("AudioStreamingIsochronousEndPoint.rs");
include!("AudioStreamingIsochronousEndPointParseError.rs");
include!("LockDelay.rs");
include!("Version1AudioStreamingIsochronousEndPoint.rs");
include!("Version1AudioStreamingIsochronousEndPointParseError.rs");
include!("Version2AudioStreamingIsochronousEndPoint.rs");
include!("Version2AudioStreamingIsochronousEndPointParseError.rs");
include!("Version3AudioStreamingIsochronousEndPoint.rs");
include!("Version3AudioStreamingIsochronousEndPointParseError.rs");
