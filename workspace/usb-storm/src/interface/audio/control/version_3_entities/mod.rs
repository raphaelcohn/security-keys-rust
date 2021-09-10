// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


use crate::collections::Bytes;
use crate::interface::audio::{Version3AudioDynamicStringDescriptorIdentifier, Control};
use serde::Deserialize;
use serde::Serialize;
use std::error;
use std::fmt::Debug;
use std::fmt::Display;
use std::fmt::Formatter;
use std::fmt;
use std::hash::Hash;
use std::num::NonZeroU16;
use std::num::NonZeroU8;
use super::entities::ClockEntity;
use super::entities::Entities;
use super::entities::Entity;
use super::entities::TerminalEntity;
use super::entities::UnitEntity;
use super::EntityDescriptors;
use super::EntityDescriptorParseError;
use super::entity_index;
use super::entity_identifiers::ClockEntityIdentifier;
use super::entity_identifiers::EntityIdentifier;
use super::entity_identifiers::PowerDomainEntityIdentifier;
use super::entity_identifiers::TerminalEntityIdentifier;
use super::entity_identifiers::UnitEntityIdentifier;
use super::entity_identifiers::UnitOrTerminalEntityIdentifier;
use super::parse_entity_descriptor;
use super::terminal_types::InputTerminalType;
use super::terminal_types::OutputTerminalType;
use crate::device::DeviceConnection;
use crate::device::DeadOrAlive;
use crate::device::DeadOrAlive::Alive;
use crate::interface::audio::control::entities::{Version3Entity, InputTerminalEntity, OutputTerminalEntity, MixerUnitEntity, FeatureUnitEntity, ExtensionUnitEntity, SelectorUnitEntity, ProcessingUnitEntity, SamplingRateConverterUnitEntity, MultiplierClockEntity, SelectorClockEntity, SourceClockEntity};


include!("ClusterDescriptorIdentifier.rs");
include!("TerminalControls.rs");
include!("TerminalControlsParseError.rs");
include!("TerminalEntityCommon.rs");
include!("Version3EffectUnitEntity.rs");
include!("Version3EntityDescriptorParseError.rs");
include!("Version3EntityDescriptors.rs");
include!("Version3ExtensionUnitEntity.rs");
include!("Version3FeatureUnitEntity.rs");
include!("Version3InputTerminalEntity.rs");
include!("Version3MixerUnitEntity.rs");
include!("Version3MultiplierClockEntity.rs");
include!("Version3OutputTerminalEntity.rs");
include!("Version3PowerDomainEntity.rs");
include!("Version3ProcessingUnitEntity.rs");
include!("Version3SamplingRateConverterUnitEntity.rs");
include!("Version3SelectorClockEntity.rs");
include!("Version3SelectorUnitEntity.rs");
include!("Version3SourceClockEntity.rs");
include!("Version3TerminalEntity.rs");
