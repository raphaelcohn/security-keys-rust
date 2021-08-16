// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


#[derive(Debug, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
#[allow(missing_docs)]
pub struct InputLogicalAudioChannelClusters(Vec<Option<UnitOrTerminalEntityIdentifier>>);

impl Deref for InputLogicalAudioChannelClusters
{
	type Target = [Option<UnitOrTerminalEntityIdentifier>];
	
	#[inline(always)]
	fn deref(&self) -> &Self::Target
	{
		&self.0
	}
}

impl InputLogicalAudioChannelClusters
{
	#[allow(missing_docs)]
	#[inline(always)]
	pub fn input_logical_audio_channel_cluster(&self, input_pin: InputPinNumber) -> Option<Option<UnitOrTerminalEntityIdentifier>>
	{
		let index = (input_pin.get() - 1) as usize;
		match self.get(index)?
		{
			None => Some(None),
			
			Some(unit_or_terminal_entity_identifier) => Some(Some(*unit_or_terminal_entity_identifier))
		}
	}
	
	/// Iterate over this to derive `n`; `n` is number of input channels.
	#[inline(always)]
	pub fn iterate(&self) -> impl '_ + Iterator<Item=(InputPinNumber, Option<UnitOrTerminalEntityIdentifier>)>
	{
		self.iter().enumerate().map(|(index, source)| (new_non_zero_u8((index + 1) as u8), source.as_ref().map(|source| *source)))
	}
	
	/// Number of audio channel clusters entering the mixer unit.
	#[inline(always)]
	pub fn number_of_input_logical_audio_channel_clusters(&self) -> usize
	{
		self.len()
	}
	
	#[inline(always)]
	pub(crate) fn version_1_parse<E: error::Error>(p: usize, entity_body: &[u8], start_index: usize, error: impl FnOnce(TryReserveError) -> E) -> Result<Self, E>
	{
		Self::parse(p, entity_body, start_index).map_err(error)
	}
	
	#[inline(always)]
	pub(crate) fn version_2_parse(p: usize, entity_body: &[u8], start_index: usize) -> Result<Self, Version2EntityDescriptorParseError>
	{
		Self::parse(p, entity_body, start_index).map_err(Version2EntityDescriptorParseError::CouldNotAllocateMemoryForSources)
	}
	
	#[inline(always)]
	fn parse(p: usize, entity_body: &[u8], start_index: usize) -> Result<Self, TryReserveError>
	{
		let input_logical_audio_channel_clusters = Vec::new_populated(p, |cause| cause, |cluster_index|
		{
			Ok(entity_body.optional_non_zero_u8(entity_index_non_constant(start_index + cluster_index)).map(UnitOrTerminalEntityIdentifier::new))
		})?;
		
		Ok(Self(input_logical_audio_channel_clusters))
	}
}
