// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


use crate::collections::Bytes;
use crate::collections::VecExt;
use crate::device::DeadOrAlive::Alive;
use crate::device::DeadOrAlive;
use crate::interface::audio::control::ChannelControlsByChannelNumber;
use crate::interface::audio::control::DescriptorEntityMinimumLength;
use crate::interface::audio::control::EntityDescriptorParseError;
use crate::interface::audio::control::EntityDescriptors;
use crate::interface::audio::control::entities::Entities;
use crate::interface::audio::control::entity_identifiers::EntityIdentifier;
use crate::interface::audio::control::entity_index_non_constant;
use crate::interface::audio::control::parse_entity_descriptor;
use crate::string::StringFinder;
use likely::unlikely;
use self::clock::multiplier::Version2MultiplierClockEntity;
use self::clock::multiplier::Version2MultiplierClockEntityParseError;
use self::clock::selector::Version2SelectorClockEntity;
use self::clock::selector::Version2SelectorClockEntityParseError;
use self::clock::source::Version2SourceClockEntity;
use self::clock::source::Version2SourceClockEntityParseError;
use self::terminal::input::Version2InputTerminalEntity;
use self::terminal::input::Version2InputTerminalEntityParseError;
use self::terminal::output::Version2OutputTerminalEntity;
use self::terminal::output::Version2OutputTerminalEntityParseError;
use self::unit::effect::Version2EffectUnitEntity;
use self::unit::effect::Version2EffectUnitEntityParseError;
use self::unit::feature::Version2FeatureUnitEntity;
use self::unit::feature::Version2FeatureUnitEntityParseError;
use self::unit::mixer::Version2MixerUnitEntity;
use self::unit::mixer::Version2MixerUnitEntityParseError;
use self::unit::processing::Version2ProcessingUnitEntity;
use self::unit::processing::Version2ProcessingUnitEntityParseError;
use self::unit::sampling_rate_converter::Version2SamplingRateConverterUnitEntity;
use self::unit::sampling_rate_converter::Version2SamplingRateConverterUnitEntityParseError;
use self::unit::selector::Version2SelectorUnitEntity;
use self::unit::selector::Version2SelectorUnitEntityParseError;
use serde::Deserialize;
use serde::Serialize;
use std::collections::HashSet;
use std::collections::TryReserveError;
use std::error;
use std::fmt::Debug;
use std::fmt::Display;
use std::fmt::Formatter;
use std::fmt;
use std::mem::size_of;


/// Clock.
pub mod clock;


/// Terminal.
pub mod terminal;


/// Unit.
pub mod unit;


/// Logical audio channel cluster.
pub mod logical_audio_channel_cluster;


include!("parse_controls_by_channel_number.rs");
include!("Version2EntityDescriptorParseError.rs");
include!("Version2EntityDescriptors.rs");
