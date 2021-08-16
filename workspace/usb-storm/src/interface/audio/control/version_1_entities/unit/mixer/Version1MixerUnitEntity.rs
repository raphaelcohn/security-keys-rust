// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// A mixer unit entity.
#[derive(Debug, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Version1MixerUnitEntity
{
	input_logical_audio_channel_clusters: InputLogicalAudioChannelClusters,
	
	output_logical_audio_channel_cluster: Version1LogicalAudioChannelCluster,
	
	mixer_controls_bit_map: Vec<u8>,
	
	description: Option<LocalizedStrings>,
}

impl Entity for Version1MixerUnitEntity
{
	type EntityIdentifier = UnitEntityIdentifier;
	
	type ParseError = Version1EntityDescriptorParseError;
	
	#[inline(always)]
	fn cast_entity_identifier(value: EntityIdentifier) -> Self::EntityIdentifier
	{
		unsafe { transmute(value) }
	}
	
	#[inline(always)]
	fn parse(entity_body: &[u8], string_finder: &StringFinder) -> Result<DeadOrAlive<Self>, Self::ParseError>
	{
		Ok(Self::parse_inner(entity_body, string_finder)?)
	}
}

impl UnitEntity for Version1MixerUnitEntity
{
}

impl Version1MixerUnitEntity
{
	#[allow(missing_docs)]
	#[inline(always)]
	pub fn input_logical_audio_channel_clusters(&self) -> &InputLogicalAudioChannelClusters
	{
		&self.input_logical_audio_channel_clusters
	}
	
	#[allow(missing_docs)]
	#[inline(always)]
	pub const fn output_logical_audio_channel_cluster(&self) -> &Version1LogicalAudioChannelCluster
	{
		&self.output_logical_audio_channel_cluster
	}
	
	/// `m` is number of output channels; it is supposed to be between 1 and 254 inclusive.
	#[inline(always)]
	pub fn m(&self) -> u8
	{
		self.output_logical_audio_channel_cluster.len() as u8
	}
	
	/// If a bit at position `[u, v]` is set, this means that the Mixer Unit contains a programmable mixing Control that connects input channel `u` to output channel `v`.
	/// If bit `[u, v]` is clear, this indicates that the connection between input channel `u` and output channel `v` is non-programmable.
	///
	/// The valid range for `u` is from one to `n`.
	/// The valid range for `v` is from one to `m`.
	#[inline(always)]
	pub fn is_a_programmable_mixing_control(&self, _input_channel_number_u: LogicalAudioChannelNumber, _output_channel_number_v: LogicalAudioChannelNumber) -> bool
	{
		unimplemented!();
	}
	
	#[allow(missing_docs)]
	#[inline(always)]
	pub const fn description(&self) -> Option<&LocalizedStrings>
	{
		self.description.as_ref()
	}
	
	#[inline(always)]
	fn parse_inner(entity_body: &[u8], string_finder: &StringFinder) -> Result<DeadOrAlive<Self>, Version1MixerUnitEntityParseError>
	{
		use Version1MixerUnitEntityParseError::*;
		
		let p = parse_p::<DescriptorEntityMinimumLength>(entity_body);
		
		/// 10.
		const MinimumBLength: usize = Version1EntityDescriptors::MixerUnitMinimumBLength as usize;
		
		let N =
		{
			let bLength = DescriptorEntityMinimumLength + entity_body.len();
			
			// bLength = 10 + p + N
			// Thus N = (bLength - 10 - p)
			(bLength - MinimumBLength).checked_sub(p).ok_or(BLengthTooShort)?
		};
		
		Ok
		(
			Alive
			(
				Self
				{
					input_logical_audio_channel_clusters: InputLogicalAudioChannelClusters::parse(p, entity_body, 5, CouldNotAllocateMemoryForSources)?,
					
					output_logical_audio_channel_cluster: return_ok_if_dead!(Version1LogicalAudioChannelCluster::parse(5 + p, string_finder, entity_body)?),
					
					mixer_controls_bit_map: Vec::new_from(entity_body.bytes(entity_index_non_constant(9 + p), N)).map_err(CouldNotAllocateMemoryForControls)?,
					
					description: return_ok_if_dead!(string_finder.find_string(entity_body.u8(entity_index_non_constant(9 + p + N))).map_err(InvalidDescriptionString)?),
				}
			)
		)
	}
}
