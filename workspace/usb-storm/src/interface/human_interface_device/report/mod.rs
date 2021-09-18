// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


use crate::collections::TryClone;
use crate::collections::VecExt;
use crate::string::LocalizedStrings;
use likely::unlikely;
use self::main_item_common::InputMainItem;
use self::main_item_common::OutputOrFeatureMainItem;
use self::main_item_common::ReservedMainItem;
use self::main_item_common::ReservedMainItemTag;
use self::parsing::DataWidth;
use self::parsing::LongItemParseError;
use self::parsing::ReportCountParseError;
use self::parsing::ReportIdentifierParseError;
use self::parsing::ReportParseError;
use self::parsing::ReportSizeParseError;
use self::units::PhysicalUnit;
use self::usages::Usage;
use serde::Deserialize;
use serde::Serialize;
use std::cmp::Ordering;
use std::collections::TryReserveError;
use std::convert::TryFrom;
use std::fmt::Debug;
use std::hash::Hash;
use std::num::NonZeroU16;
use std::num::NonZeroU32;
use std::num::NonZeroU8;
use std::ops::Deref;
use std::ops::RangeInclusive;
use swiss_army_knife::non_zero::new_non_zero_u16;
use swiss_army_knife::non_zero::new_non_zero_u32;
use swiss_army_knife::non_zero::new_non_zero_u8;


/// Main item common.
pub mod main_item_common;


/// Parsing.
pub mod parsing;


/// Units.
pub mod units;


/// Usages.
pub mod usages;


include!("CollectionCommon.rs");include!("CollectionDescription.rs");
include!("CollectionMainItem.rs");
include!("CollectionReportItems.rs");
include!("DesignatorIndex.rs");
include!("HasReportItems.rs");
include!("InclusiveRange.rs");
include!("LongItem.rs");
include!("LongItemTag.rs");
include!("Report.rs");
include!("ReportCount.rs");
include!("ReportItems.rs");
include!("ReportIdentifier.rs");
include!("ReportSize.rs");
include!("ReservedGlobalItem.rs");
include!("ReservedLocalItem.rs");
include!("ReservedLocalItemTag.rs");
