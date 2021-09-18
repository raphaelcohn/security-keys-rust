// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


use self::virtual_reality_controls::VirtualRealityControlsUsage;
use serde::Deserialize;
use serde::Serialize;
use std::mem::transmute;
use std::num::NonZeroU16;
use crate::interface::human_interface_device::report::parsing::ParsingUsagePage;


/// Virtual reality controls.
pub mod virtual_reality_controls;


include!("ButtonUsage.rs");
include!("CameraControlUsage.rs");
include!("FidoAllianceUsage.rs");
include!("OrdinalUsage.rs");
include!("Ucs2CodePoint.rs");
include!("Usage.rs");
include!("UsageIdentifier.rs");
