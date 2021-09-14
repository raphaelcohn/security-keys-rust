// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


use crate::collections::Bytes;
use crate::collections::TryClone;
use crate::collections::VecExt;
use crate::control_transfers::descriptors::GetDescriptorError;
use crate::control_transfers::descriptors::get_human_interface_device_report_interface_descriptor;
use crate::device::DeadOrAlive::Alive;
use crate::device::DeadOrAlive;
use crate::device::DeviceConnection;
use crate::device::ReusableBuffer;
use crate::interface::InterfaceNumber;
use crate::serde::AllocErrorRemote;
use crate::serde::TryReserveErrorRemote;
use crate::string::GetLocalizedStringError;
use crate::string::LocalizedStrings;
use likely::unlikely;
use self::main_item_common::OutputOrFeatureMainItem;
use serde::Deserialize;
use serde::Serialize;
use std::alloc::AllocError;
use std::borrow::Borrow;
use std::borrow::Cow;
use std::cmp::Ordering;
use std::collections::TryReserveError;
use std::error;
use std::fmt::Debug;
use std::fmt::Display;
use std::fmt::Formatter;
use std::fmt;
use std::mem::MaybeUninit;
use std::mem::take;
use std::mem::transmute;
use std::num::NonZeroU32;
use std::num::NonZeroU16;
use std::ops::Deref;
use std::ops::RangeInclusive;
use std::ptr::read;
use std::rc::Rc;
use swiss_army_knife::get_unchecked::GetUnchecked;
use swiss_army_knife::non_zero::new_non_zero_u16;
use swiss_army_knife::non_zero::new_non_zero_u32;
use self::main_item_common::InputMainItem;
use self::main_item_common::ReservedMainItemTag;
use self::main_item_common::ReservedMainItem;
use self::units::Unit;
use self::units::UnitExponent;
use std::hash::Hash;


/// Main item common.
pub mod main_item_common;


/// Units.
pub mod units;


include!("CollectionCommon.rs");
include!("CollectionDescription.rs");
include!("CollectionMainItem.rs");
include!("DataWidth.rs");
include!("DesignatorIndex.rs");
include!("GlobalItemParseError.rs");
include!("InclusiveRange.rs");
include!("ItemStateTable.rs");
include!("LocalItemParseError.rs");
include!("LongItem.rs");
include!("LongItemTag.rs");
include!("MainItem.rs");
include!("ParsingLocalItems.rs");
include!("ParsingLocalItemsSet.rs");
include!("ParsingGlobalItems.rs");
include!("ParsingGlobalItemsSet.rs");
include!("ParsingUsage.rs");
include!("Report.rs");
include!("ReportItems.rs");
include!("ReportIdentifier.rs");
include!("ReportParseError.rs");
include!("ReportParser.rs");
include!("ReportSize.rs");
include!("ReservedGlobalItem.rs");
include!("ReservedLocalItem.rs");
include!("ReservedLocalItemTag.rs");
include!("ShortItemType.rs");
include!("Stack.rs");
include!("Usage.rs");
include!("UsageIdentifier.rs");
include!("UsagePage.rs");
