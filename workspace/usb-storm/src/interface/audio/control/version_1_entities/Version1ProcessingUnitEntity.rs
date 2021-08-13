// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// A processing unit entity.
#[derive(Debug, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Version1ProcessingUnitEntity
{
	input_logical_audio_channel_clusters: InputLogicalAudioChannelClusters,
	
	output_logical_audio_channel_cluster: Version1LogicalAudioChannelCluster,
	
	enable: bool,
	
	process_type: ProcessType,
	
	description: Option<LocalizedStrings>,
}

impl Entity for Version1ProcessingUnitEntity
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
		use Version1EntityDescriptorParseError::*;
		
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
		
		let controls_bytes_size =
		{
			let control_size_index = DescriptorEntityMinimumLength + ProcessTypeSize + sources_size + OutputClusterSize;
			if unlikely!(entity_index_non_constant(control_size_index) >= entity_body.len())
			{
				return Err(ProcessingUnitPIsTooLarge);
			}
			parse_control_size(entity_body, control_size_index, ProcessingUnitControlSizeIsZero)?
		};
		
		// entity_body.len() == ProcessTypeSize + sources_size + OutputClusterSize + ControlSizeSize + controls_bytes_size + StringDescriptorSize + process_specific_size;
		let controls_bytes_size_plus_process_specific_size = entity_body.len().checked_sub(ProcessTypeSize + sources_size + OutputClusterSize + ControlSizeSize + StringDescriptorSize).ok_or(ProcessingUnitHasTooFewBytesForControlsAndProcessSpecificData)?;
		let process_specific_size = controls_bytes_size_plus_process_specific_size.checked_sub(controls_bytes_size.get()).ok_or(ProcessingUnitHasTooFewBytesForProcessSpecificData)?;
		
		let bmControls = entity_body.bytes(ProcessTypeSize + sources_size + OutputClusterSize + ControlSizeSize, controls_bytes_size.get());
		let enable = (bmControls.get_unchecked_value_safe(0) & 0b1) != 0b0;
		
		let output_logical_audio_channel_cluster = return_ok_if_dead!(Version1LogicalAudioChannelCluster::parse(7 + p, string_finder, entity_body)?);
		Ok
		(
			Alive
			(
				Self
				{
					input_logical_audio_channel_clusters: InputLogicalAudioChannelClusters::version_1_parse(p, entity_body, 7)?,
					
					enable,
					
					process_type:
					{
						let process_type_specific_bytes = entity_body.get_unchecked_range_safe(ProcessTypeSize + sources_size + OutputClusterSize + ControlSizeSize + controls_bytes_size.get() + StringDescriptorSize .. );
						debug_assert_eq!(process_type_specific_bytes.len(), process_specific_size);
						match entity_body.u16(entity_index::<DescriptorEntityMinimumLength>())
						{
							0x00 => ProcessType::parse_undefined(bmControls, process_type_specific_bytes)?,
							
							0x01 => ProcessType::parse_up_down_mix(bmControls, process_type_specific_bytes, p, &output_logical_audio_channel_cluster)?,
							
							0x02 => ProcessType::parse_dolby_pro_logic(bmControls, process_type_specific_bytes, p, &output_logical_audio_channel_cluster)?,
							
							0x03 => ProcessType::parse_three_dimensional_stereo_extended(bmControls, process_type_specific_bytes, p, &output_logical_audio_channel_cluster)?,
							
							0x04 => ProcessType::parse_reverberation(bmControls, process_type_specific_bytes, p)?,
							
							0x05 => ProcessType::parse_chorus(bmControls, process_type_specific_bytes, p)?,
							
							0x06 => ProcessType::parse_dynamic_range_compressor(bmControls, process_type_specific_bytes, p)?,
							
							process_type_code @ _ => ProcessType::parse_unrecognized(bmControls, process_type_specific_bytes, process_type_code)?,
						}
					},
					
					output_logical_audio_channel_cluster,
					
					description: return_ok_if_dead!(string_finder.find_string(entity_body.u8(ProcessTypeSize + sources_size + OutputClusterSize + ControlSizeSize + controls_bytes_size.get())).map_err(InvalidDescriptionString)?),
				}
			)
		)
	}
}

impl UnitEntity for Version1ProcessingUnitEntity
{
}

impl Version1ProcessingUnitEntity
{
	#[allow(missing_docs)]
	#[inline(always)]
	pub const fn description(&self) -> Option<&LocalizedStrings>
	{
		self.description.as_ref()
	}
	
	#[allow(missing_docs)]
	#[inline(always)]
	pub const fn enable(&self) -> bool
	{
		self.enable
	}
	
	#[allow(missing_docs)]
	#[inline(always)]
	pub const fn process_type(&self) -> &ProcessType
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
	pub const fn output_logical_audio_channel_cluster(&self) -> &Version1LogicalAudioChannelCluster
	{
		&self.output_logical_audio_channel_cluster
	}
}
