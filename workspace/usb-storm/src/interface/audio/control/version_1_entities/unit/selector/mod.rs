// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


use crate::collections::Bytes;
use crate::device::DeadOrAlive::Alive;
use crate::device::DeadOrAlive;
use crate::interface::audio::control::entities::{Entity, DescribedEntity, Version1Entity, SelectorUnitEntity};
use crate::interface::audio::control::entities::UnitEntity;
use crate::interface::audio::control::entity_identifiers::EntityIdentifier;
use crate::interface::audio::control::entity_identifiers::UnitEntityIdentifier;
use crate::interface::audio::control::logical_audio_channels::InputLogicalAudioChannelClusters;
use crate::interface::audio::control::{parse_p, DescriptorEntityMinimumLength, entity_index_non_constant};
use crate::interface::audio::control::version_1_entities::Version1EntityDescriptors;
use crate::interface::audio::control::version_1_entities::Version1EntityDescriptorParseError;
use crate::serde::TryReserveErrorRemote;
use crate::string::GetLocalizedStringError;
use crate::string::LocalizedStrings;
use crate::device::DeviceConnection;
use likely::unlikely;
use serde::Deserialize;
use serde::Serialize;
use std::collections::TryReserveError;
use std::error;
use std::fmt::Debug;
use std::fmt::Display;
use std::fmt::Formatter;
use std::fmt;


include!("Version1SelectorUnitEntity.rs");
include!("Version1SelectorUnitEntityParseError.rs");
