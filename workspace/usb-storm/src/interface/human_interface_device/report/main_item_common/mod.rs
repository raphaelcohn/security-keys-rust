// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


use serde::Deserialize;
use serde::Serialize;
use super::HasReportItems;
use std::mem::transmute;
use std::ops::Deref;
use crate::interface::human_interface_device::report::DataWidth;
use crate::interface::human_interface_device::report::ReportItems;


include!("AbsoluteOrRelative.rs");
include!("ArrayOrVariable.rs");
include!("BitFieldOrBufferedBytes.rs");
include!("DataOrConstant.rs");
include!("InputMainItem.rs");
include!("is_array.rs");
include!("MainItemCommon.rs");
include!("LinearOrNonLinear.rs");
include!("OutputOrFeatureOrInputVariableCommon.rs");
include!("OutputOrFeatureMainItem.rs");
include!("parse_boolean.rs");
include!("parse_boolean_enum.rs");
include!("ReservedMainItem.rs");
include!("ReservedMainItemTag.rs");
