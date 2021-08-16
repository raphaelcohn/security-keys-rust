// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// A processing unit entity.
#[derive(Debug, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Version2ProcessingUnitEntity
{
	input_logical_audio_channel_clusters: InputLogicalAudioChannelClusters,
	
	output_logical_audio_channel_cluster: Version2LogicalAudioChannelCluster,
	
	enable_control: Control,
	
	process_type: Version2ProcessType,
	
	description: Option<LocalizedStrings>,
}

impl Entity for Version2ProcessingUnitEntity
{
	type EntityIdentifier = UnitEntityIdentifier;
	
	type ParseError = Version2EntityDescriptorParseError;
	
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

impl UnitEntity for Version2ProcessingUnitEntity
{
}

impl Version2ProcessingUnitEntity
{
	#[allow(missing_docs)]
	#[inline(always)]
	pub const fn description(&self) -> Option<&LocalizedStrings>
	{
		self.description.as_ref()
	}
	
	#[allow(missing_docs)]
	#[inline(always)]
	pub const fn enable_control(&self) -> Control
	{
		self.enable_control
	}
	
	#[allow(missing_docs)]
	#[inline(always)]
	pub const fn process_type(&self) -> &Version2ProcessType
	{
		&self.process_type
	}
	
	#[allow(missing_docs)]
	#[inline(always)]
	pub const fn input_logical_audio_channel_clusters(&self) -> &InputLogicalAudioChannelClusters
	{
		&self.input_logical_audio_channel_clusters
	}
	
	#[allow(missing_docs)]
	#[inline(always)]
	pub const fn output_logical_audio_channel_cluster(&self) -> &Version2LogicalAudioChannelCluster
	{
		&self.output_logical_audio_channel_cluster
	}
	
	#[inline(always)]
	fn parse_inner(entity_body: &[u8], string_finder: &StringFinder) -> Result<DeadOrAlive<Self>, Version2ProcessingUnitEntityParseError>
	{
		use Version2ProcessingUnitEntityParseError::*;
		
		let p =
		{
			const PIndex: usize = DescriptorEntityMinimumLength + ProcessTypeSize;
			parse_p::<PIndex>(entity_body)
		};
		
		const ProcessTypeSize: usize = 2;
		
		let iProcessingIndex = entity_index_non_constant(16 + p);
		if unlikely!(iProcessingIndex >= entity_body.len())
		{
			Err(PIsTooLarge)?
		}
		
		let bmControls = entity_body.u32(entity_index_non_constant(13 + p));
		let output_logical_audio_channel_cluster = return_ok_if_dead!(Version2LogicalAudioChannelCluster::parse(7 + p, string_finder, entity_body).map_err(LogicalAudioChannelClusterParse)?);
		Ok
		(
			Alive
			(
				Self
				{
					input_logical_audio_channel_clusters: InputLogicalAudioChannelClusters::parse(p, entity_body, 7, CouldNotAllocateMemoryForSources)?,
					
					enable_control: Control::parse_u32(bmControls, 0, EnableControlInvalid)?,
					
					process_type: Self::parse_process_type(entity_body, iProcessingIndex, bmControls, p, &output_logical_audio_channel_cluster)?,
					
					output_logical_audio_channel_cluster,
					
					description: return_ok_if_dead!(string_finder.find_string(entity_body.u8(iProcessingIndex)).map_err(InvalidDescriptionString)?),
				}
			)
		)
	}
	
	#[inline(always)]
	fn parse_process_type(entity_body: &[u8], iProcessingIndex: usize, bmControls: u32, p: usize, output_logical_audio_channel_cluster: &Version2LogicalAudioChannelCluster) -> Result<Version2ProcessType, Version2ProcessTypeParseError>
	{
		let process_type_specific_bytes = entity_body.get_unchecked_range_safe((iProcessingIndex + 1) .. );
		let process_type_code = entity_body.u16(entity_index::<DescriptorEntityMinimumLength>());
		Ok
		(
			match process_type_code
			{
				0x00 => Version2ProcessType::parse_undefined(bmControls, process_type_specific_bytes)?,
				
				0x01 => Version2ProcessType::parse_up_down_mix(bmControls, process_type_specific_bytes, p, output_logical_audio_channel_cluster)?,
				
				0x02 => Version2ProcessType::parse_dolby_pro_logic(bmControls, process_type_specific_bytes, p, output_logical_audio_channel_cluster)?,
				
				0x03 => Version2ProcessType::parse_stereo_extender(bmControls, process_type_specific_bytes, p)?,
				
				_ => Version2ProcessType::parse_unrecognized(bmControls, process_type_specific_bytes, process_type_code)?,
			}
		)
	}
}
