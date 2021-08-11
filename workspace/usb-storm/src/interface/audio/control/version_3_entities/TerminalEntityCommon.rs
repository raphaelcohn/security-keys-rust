// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// A terminal entity.
#[derive(Debug, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
#[allow(missing_docs)]
pub struct TerminalEntityCommon
{
	clock_source: Option<ClockEntityIdentifier>,
	
	controls: TerminalControls,
	
	cluster_descriptor_identifier: u16,
	
	extended_terminal_descriptor_identifier: Option<NonZeroU16>,
	
	connectors_descriptor_identifier: Option<NonZeroU16>,
	
	description: Option<Version3AudioDynamicStringDescriptorIdentifier>,
}

impl TerminalEntityCommon
{
	#[allow(missing_docs)]
	#[inline(always)]
	pub const fn clock_source(&self) -> Option<ClockEntityIdentifier>
	{
		self.clock_source
	}
	
	#[allow(missing_docs)]
	#[inline(always)]
	pub const fn controls(&self) -> TerminalControls
	{
		self.controls
	}
	
	#[allow(missing_docs)]
	#[inline(always)]
	pub const fn cluster_descriptor_identifier(&self) -> u16
	{
		self.cluster_descriptor_identifier
	}
	
	#[allow(missing_docs)]
	#[inline(always)]
	pub const fn extended_terminal_descriptor_identifier(&self) -> Option<NonZeroU16>
	{
		self.extended_terminal_descriptor_identifier
	}
	
	#[allow(missing_docs)]
	#[inline(always)]
	pub const fn connectors_descriptor_identifier(&self) -> Option<NonZeroU16>
	{
		self.connectors_descriptor_identifier
	}
	
	#[allow(missing_docs)]
	#[inline(always)]
	pub const fn string_descriptor_identifier(&self) -> Option<Version3AudioDynamicStringDescriptorIdentifier>
	{
		self.description
	}
}
