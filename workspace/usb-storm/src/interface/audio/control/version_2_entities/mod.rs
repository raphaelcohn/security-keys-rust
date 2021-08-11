// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


use super::Entity;
use super::Entities;
use super::EntityDescriptors;
use super::EntityDescriptorParseError;
use super::parse_entity_descriptor;
use super::TerminalEntity;
use super::entity_identifiers::EntityIdentifier;
use std::collections::HashSet;
use std::error;
use std::fmt;
use std::fmt::Debug;
use std::fmt::Display;
use std::fmt::Formatter;
use crate::string::StringFinder;
use crate::device::DeadOrAlive::Alive;
use crate::device::DeadOrAlive;


include!("Version2EntityDescriptorParseError.rs");
include!("Version2EntityDescriptors.rs");
