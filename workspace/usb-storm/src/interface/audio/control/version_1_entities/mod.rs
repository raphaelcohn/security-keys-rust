// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


use crate::device::DeadOrAlive::Alive;
use crate::device::DeadOrAlive;
use crate::interface::audio::control::{EntityDescriptorParseError, entity_index_non_constant};
use crate::interface::audio::control::EntityDescriptors;
use crate::interface::audio::control::entities::Entities;
use crate::interface::audio::control::parse_entity_descriptor;
use crate::string::StringFinder;
use self::terminal::input::Version1InputTerminalEntity;
use self::terminal::input::Version1InputTerminalEntityParseError;
use self::terminal::output::Version1OutputTerminalEntity;
use self::terminal::output::Version1OutputTerminalEntityParseError;
use self::unit::extension::Version1ExtensionUnitEntity;
use self::unit::extension::Version1ExtensionUnitEntityParseError;
use self::unit::feature::Version1FeatureUnitEntity;
use self::unit::feature::Version1FeatureUnitEntityParseError;
use self::unit::mixer::Version1MixerUnitEntity;
use self::unit::mixer::Version1MixerUnitEntityParseError;
use self::unit::processing::Version1ProcessingUnitEntity;
use self::unit::processing::Version1ProcessingUnitEntityParseError;
use self::unit::selector::Version1SelectorUnitEntity;
use self::unit::selector::Version1SelectorUnitEntityParseError;
use serde::Deserialize;
use serde::Serialize;
use std::error;
use std::fmt::Debug;
use std::fmt::Display;
use std::fmt::Formatter;
use std::fmt;
use crate::collections::Bytes;
use std::num::NonZeroUsize;
use swiss_army_knife::non_zero::new_non_zero_usize;


/// Logical audio channel cluster.
pub mod logical_audio_channel_cluster;


/// Terminal.
pub mod terminal;


/// Unit.
pub mod unit;


include!("parse_control_size.rs");
include!("Version1EntityDescriptorParseError.rs");
include!("Version1EntityDescriptors.rs");
