// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// An input terminal entity.
#[derive(Debug, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
#[allow(missing_docs)]
pub struct Version1ProcessingUnitEntity
{
	input_logical_audio_channel_clusters: InputLogicalAudioChannelClusters,
	
	output_logical_audio_channel_cluster: LogicalAudioChannelCluster,
	
	enable_processing: bool,
	
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
		
		let p =
		{
			const PIndex: usize = DescriptorEntityMinimumLength + ProcessTypeSize;
			parse_p::<PIndex>(entity_body)
		};
		
		let controls_bytes_size =
		{
			let control_size_index = DescriptorEntityMinimumLength + ProcessTypeSize + sources_size + OutputClusterSize;
			if unlikely!(adjusted_index_non_constant(control_size_index) >= entity_body.len())
			{
				return Err(ProcessingUnitPIsTooLarge);
			}
			parse_control_size(entity_body, control_size_index, ProcessingUnitControlSizeIsZero)?
		};
		
		// entity_body.len() == ProcessTypeSize + sources_size + OutputClusterSize + ControlSizeSize + controls_bytes_size + StringDescriptorSize + process_specific_size;
		let controls_bytes_size_plus_process_specific_size = entity_body.len().checked_sub(ProcessTypeSize + sources_size + OutputClusterSize + ControlSizeSize + StringDescriptorSize).ok_or(ProcessingUnitHasTooFewBytesForControlsAndProcessSpecificData)?;
		let process_specific_size = controls_bytes_size_plus_process_specific_size.checked_sub(controls_bytes_size.get()).ok_or(ProcessingUnitHasTooFewBytesForProcessSpecificData)?;
		
		let bmControls = entity_body.bytes_unadjusted(ProcessTypeSize + sources_size + OutputClusterSize + ControlSizeSize, controls_bytes_size.get());
		let enable_processing = (bmControls.get_unchecked_value_safe(0) & 0b1) != 0b0;
		
		
		let output_logical_audio_channel_cluster = return_ok_if_dead!(LogicalAudioChannelCluster::parse(7 + p, string_finder, entity_body)?);
		Ok
		(
			Alive
			(
				Self
				{
					input_logical_audio_channel_clusters: InputLogicalAudioChannelClusters::parse(p, entity_body, 7)?,
					
					enable_processing,
					
					process_type:
					{
						let process_type_specific_bytes = entity_body.get_unchecked_range_safe(ProcessTypeSize + sources_size + OutputClusterSize + ControlSizeSize + controls_bytes_size.get() + StringDescriptorSize .. );
						match entity_body.u16_unadjusted(adjusted_index::<DescriptorEntityMinimumLength>())
						{
							0x00 => ProcessType::parse_undefined(bmControls, process_type_specific_bytes)?,
							
							0x01 => ProcessType::parse_up_down_mix(bmControls, process_type_specific_bytes, p)?,
							
							0x02 => ProcessType::parse_dolby_pro_logic(bmControls, process_type_specific_bytes, p)?,
							
							0x03 => ProcessType::parse_three_dimensional_stereo_extended(bmControls, process_type_specific_bytes, p, &output_logical_audio_channel_cluster)?,
							
							0x04 => ProcessType::parse_reverberation(bmControls, process_type_specific_bytes, p)?,
							
							0x05 => ProcessType::parse_chorus(bmControls, process_type_specific_bytes, p)?,
							
							0x06 => ProcessType::parse_dynamic_range_compressor(bmControls, process_type_specific_bytes, p)?,
							
							process_type_code @ _ => ProcessType::parse_unrecognized(bmControls, process_type_specific_bytes, process_type_code)?,
						}
					},
					
					output_logical_audio_channel_cluster,
					
					description: return_ok_if_dead!(string_finder.find_string(entity_body.u8_unadjusted(ProcessTypeSize + sources_size + OutputClusterSize + ControlSizeSize + controls_bytes_size.get())).map_err(InvalidDescriptionString)?),
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
	pub const fn enable_processing(&self) -> bool
	{
		self.enable_processing
	}
	
	#[allow(missing_docs)]
	#[inline(always)]
	pub const fn process_type(&self) -> &ProcessType
	{
		&self.process_type
	}
	
	#[allow(missing_docs)]
	#[inline(always)]
	pub fn number_of_logical_channels(&self) -> usize
	{
		let length = self.controls_by_channel_number.len();
		if unlikely!(length == 0)
		{
			0
		}
		else
		{
			length - 1
		}
	}
	
	#[allow(missing_docs)]
	#[inline(always)]
	pub fn master_channel_controls(&self) -> Option<BitFlags<AudioChannelFeatureControl>>
	{
		if unlikely!(self.controls_by_channel_number.is_empty())
		{
			None
		}
		else
		{
			Some(self.controls_by_channel_number.get_unchecked_value_safe(0))
		}
	}
	
	#[allow(missing_docs)]
	#[inline(always)]
	pub fn logical_channel_controls(&self, logical_audio_channel_number: LogicalAudioChannelNumber) -> Option<BitFlags<AudioChannelFeatureControl>>
	{
		self.controls_by_channel_number.get(logical_audio_channel_number.get()).map(|control| *control)
	}
	
	#[inline(always)]
	fn parse_controls_by_channel_number(controls_bytes_length: usize, control_size: NonZeroUsize, entity_body: &[u8]) -> Result<Vec<BitFlags<AudioChannelFeatureControl>>, Version1EntityDescriptorParseError>
	{
		let number_of_channels_including_master = controls_bytes_length / control_size.get();
		
		let mut controls_by_channel_number = Vec::new_with_capacity(number_of_channels_including_master).map_err(Version1EntityDescriptorParseError::CouldNotAllocateMemoryForFeatureControls)?;
		for index in 0 .. number_of_controls
		{
			let control_bit_map = entity_body.bytes_unadjusted(6 + (index * control_size.get()), control_size.get());
			let controls = if control_size == new_non_zero_usize(1)
			{
				let lower_byte = control_bit_map.get_unchecked_value_safe(0);
				let value = lower_byte as u16;
				unsafe { BitFlags::from_bits_unchecked(value) }
			}
			else
			{
				let lower_byte = control_bit_map.get_unchecked_value_safe(0);
				let upper_byte = control_bit_map.get_unchecked_value_safe(1);
				let value = ((upper_byte as u16) << 8) | (lower_byte as u16);
				BitFlags::from_bits_truncate(value)
			};
			controls_by_channel_number.push(controls);
		}
		
		Ok(controls_by_channel_number)
	}
}
