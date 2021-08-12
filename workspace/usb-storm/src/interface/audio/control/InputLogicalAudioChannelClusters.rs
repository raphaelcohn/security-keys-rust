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
		match self.input_logical_audio_channel_clusters.get(input_pin.get() - 1)?
		{
			None => Some(None),
			
			Some(unit_or_terminal_entity_identifier) => Some(Some(*unit_or_terminal_entity_identifier))
		}
	}
	
	/// Iterate over this to derive `n`; `n` is number of input channels.
	#[inline(always)]
	pub fn iterate(&self) -> impl Iterator<Item=(InputPinNumber, Option<UnitOrTerminalEntityIdentifier>)>
	{
		self.input_logical_audio_channel_clusters.iter().enumerate().map(|(index, source)| (new_non_zero_u8((index + 1) as u8), source.as_ref().map(|source| *source)))
	}
	
	// Number of audio channel clusters entering the mixer unit.
	#[inline(always)]
	pub fn number_of_input_logical_audio_channel_clusters(&self) -> usize
	{
		self.input_logical_audio_channel_clusters.len()
	}
	
	#[inline(always)]
	fn parse(p: usize, entity_body: &[u8], start_index: usize) -> Result<Self, Version1EntityDescriptorParseError>
	{
		let mut input_logical_audio_channel_clusters = Vec::new_with_capacity(p).map_err(Version1EntityDescriptorParseError::CouldNotAllocateMemoryForSources)?;
		for cluster_index in 0 .. p
		{
			let cluster_identifier = entity_body.optional_non_zero_u8_unadjusted(adjusted_index_non_constant(start_index + cluster_index)).map(UnitOrTerminalEntityIdentifier::new);
			input_logical_audio_channel_clusters.push(cluster_identifier)
		}
		Ok(Self(input_logical_audio_channel_clusters))
	}
}
