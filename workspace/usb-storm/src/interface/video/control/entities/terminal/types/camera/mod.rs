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
use std::num::NonZeroU16;
use std::ops::RangeInclusive;
use crate::collections::{Bytes, WrappedBitFlags};
use crate::version::Version;
use crate::interface::video::control::entities::entity_index;
use std::cmp::Ordering;


include!("Camera.rs");
include!("CameraControl.rs");
include!("CameraParseError.rs");
include!("FocalLength.rs");
include!("OpticalZoom.rs");
