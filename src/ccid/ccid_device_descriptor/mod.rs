// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


use self::features::Features;
use super::UsbInterfaceAlternateSetting;
use enumflags2::bitflags;
use enumflags2::BitFlags;
use likely::likely;
use likely::unlikely;
use rusb::Version;
use std::num::NonZeroU8;
use swiss_army_knife::non_zero::new_non_zero_u8;
use std::mem::transmute;
use swiss_army_knife::get_unchecked::GetUnchecked;


pub(crate) mod features;


include!("Baud.rs");
include!("CcidDeviceDescriptor.rs");
include!("CcidProtocol.rs");
include!("Extra.rs");
include!("IsoProtocol.rs");
include!("Kilohertz.rs");
include!("LcdLayout.rs");
include!("MechanicalFeature.rs");
include!("PinSupport.rs");
include!("SynchronizationProtocol.rs");
include!("VoltageSupport.rs");
