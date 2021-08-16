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
	
	process_type: ProcessType,
	
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
		use Version2ProcessingUnitEntityParseError::*;
		
		let p =
		{
			const PIndex: usize = DescriptorEntityMinimumLength + ProcessTypeSize;
			parse_p::<PIndex>(entity_body)
		};
		
		const ProcessTypeSize: usize = 2;
		let sources_size: usize =
		{
			const PSize: usize = 1;
			const ClusterIdentifierSize: usize = 1;
			PSize + (p * ClusterIdentifierSize)
		};
		const OutputClusterSize: usize =
		{
			const NumberOfChannelsSize: usize = 1;
			const ChannelConfigSize: usize = 2;
			const ChannelNamesSize: usize = 1;
			NumberOfChannelsSize + ChannelConfigSize + ChannelNamesSize
		};
		const ControlSizeSize: usize = 1;
		const StringDescriptorSize: usize = 1;
		
		let iProcessingIndex: usize = entity_index_non_constant(16 + p);
		if unlikely!(iProcessingIndex >= entity_body.len())
		{
			Err(PIsTooLarge)?
		}
		
		let bmControls = entity_body.u32(entity_index_non_constant(13 + p));
		Ok
		(
			Alive
			(
				Self
				{
					input_logical_audio_channel_clusters: InputLogicalAudioChannelClusters::version_2_parse(p, entity_body, 7)?,
					
					output_logical_audio_channel_cluster: return_ok_if_dead!(Version2LogicalAudioChannelCluster::parse(7 + p, string_finder, entity_body)?),
					
					enable_control: Control::parse_u32(bmControls, 0, EnableControlInvalid)?,
					
					process_type:
					{
						let process_type_specific_bytes = entity_body.get_unchecked_range_safe((iProcessingIndex + 1) .. );
						debug_assert_eq!(process_type_specific_bytes.len(), process_specific_size);
						match entity_body.u16(entity_index::<DescriptorEntityMinimumLength>())
						{
							0x00 => Version2ProcessType::parse_undefined(bmControls, process_type_specific_bytes)?,
							
							0x01 => Version2ProcessType::parse_up_down_mix(bmControls, process_type_specific_bytes, p, &output_logical_audio_channel_cluster)?,
							
							0x02 => Version2ProcessType::parse_dolby_pro_logic(bmControls, process_type_specific_bytes, p, &output_logical_audio_channel_cluster)?,
							
							0x03 => Version2ProcessType::parse_stereo_extender(bmControls, process_type_specific_bytes, p, &output_logical_audio_channel_cluster)?,
							
							process_type_code @ _ => Version2ProcessType::parse_unrecognized(bmControls, process_type_specific_bytes, process_type_code)?,
						}
					},
					
					description: return_ok_if_dead!(string_finder.find_string(entity_body.u8(iProcessingIndex)).map_err(InvalidDescriptionString)?),
				}
			)
		)
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
}
