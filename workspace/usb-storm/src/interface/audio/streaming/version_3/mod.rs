// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


use enumflags2::bitflags;
use likely::unlikely;
use serde::Deserialize;
use serde::Serialize;
use std::error;
use std::fmt;
use std::fmt::Debug;
use std::fmt::Display;
use std::fmt::Formatter;
use crate::interface::audio::control::entity_identifiers::TerminalEntityIdentifier;
use crate::descriptors::verify_remaining_bytes;
use crate::descriptors::descriptor_index;
use crate::collections::{Bytes, WrappedBitFlags};
use crate::interface::audio::Control;
use crate::interface::audio::control::version_3_entities::ClusterDescriptorIdentifier;


include!("AuxillaryProtocol.rs");
include!("FrequencyRange.rs");
include!("General.rs");
include!("GeneralParseError.rs");
include!("GeneralControlsParseError.rs");
include!("Hertz.rs");
include!("ValidSamplingFrequencyRangeParseError.rs");
include!("Version3AudioFormat.rs");
include!("Version3AudioStreamingInterfaceExtraDescriptor.rs");
include!("Version3AudioStreamingInterfaceExtraDescriptorParseError.rs");
