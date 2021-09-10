// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


use crate::interface::audio::control::entities::{TerminalEntity, Version2Entity};
use crate::interface::audio::control::entity_identifiers::ClockEntityIdentifier;

/// Input.
pub mod input;


/// Output.
pub mod output;


include!("Version2TerminalEntity.rs");
