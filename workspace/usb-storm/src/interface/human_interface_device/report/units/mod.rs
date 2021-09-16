// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


use likely::likely;
use crate::integers::u4;
use serde::Deserialize;
use serde::Serialize;
use std::fmt;
use std::fmt::Debug;
use std::fmt::Display;
use std::fmt::Formatter;
use std::num::NonZeroI8;
use swiss_army_knife::non_zero::new_non_zero_i8;
use swiss_army_knife::strings::to_number::NumberAsDecimalString;
use swiss_army_knife::strings::to_number::number_as_decimal_string_formats::SuperscriptLatinNumberAsDecimalStringFormat;
use std::collections::TryReserveError;
use std::hash::Hash;
use super::parsing::DataWidth;


include!("Ampere.rs");
include!("Candela.rs");
include!("CommonUnits.rs");
include!("Exponent.rs");
include!("LengthOrAngleUnits.rs");
include!("TemperatureUnits.rs");
include!("LinearOrRotation.rs");
include!("MassUnits.rs");
include!("parse_exponent_nibble.rs");
include!("PhysicalUnit.rs");
include!("ReservedUnits.rs");
include!("System.rs");
include!("SystemOfUnits.rs");
include!("Second.rs");
include!("Unit.rs");
include!("UnitExponent.rs");
include!("Units.rs");
