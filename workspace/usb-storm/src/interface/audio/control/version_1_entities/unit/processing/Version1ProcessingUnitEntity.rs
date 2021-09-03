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
	
	process_type: Version1ProcessType,
	
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
	fn parse(entity_body: &[u8], device_connection: &DeviceConnection) -> Result<DeadOrAlive<Self>, Self::ParseError>
	{
		Ok(Self::parse_inner(entity_body, device_connection)?)
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
	pub const fn process_type(&self) -> &Version1ProcessType
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
	
	#[inline(always)]
	fn parse_inner(entity_body: &[u8], device_connection: &DeviceConnection) -> Result<DeadOrAlive<Self>, Version1ProcessingUnitEntityParseError>
	{
		use Version1ProcessingUnitEntityParseError::*;
		
		let p =
		{
			const PIndex: usize = DescriptorEntityMinimumLength + Version1ProcessingUnitEntity::ProcessTypeSize;
			parse_p::<PIndex>(entity_body)
		};
		
		let sources_size: usize =
		{
			const PSize: usize = 1;
			const ClusterIdentifierSize: usize = 1;
			PSize + (p * ClusterIdentifierSize)
		};
		
		let controls_bytes_size =
		{
			let control_size_index = DescriptorEntityMinimumLength + Self::ProcessTypeSize + sources_size + Self::OutputClusterSize;
			if unlikely!(entity_index_non_constant(control_size_index) >= entity_body.len())
			{
				Err(PIsTooLarge)?;
			}
			parse_control_size(entity_body, control_size_index, ControlSizeIsZero)?
		};
		
		// entity_body.len() == ProcessTypeSize + sources_size + OutputClusterSize + ControlSizeSize + controls_bytes_size + StringDescriptorSize + process_specific_size;
		let controls_bytes_size_plus_process_specific_size = entity_body.len().checked_sub(Self::ProcessTypeSize + sources_size + Self::OutputClusterSize + Self::ControlSizeSize + Self::StringDescriptorSize).ok_or(HasTooFewBytesForControlsAndProcessSpecificData)?;
		let process_specific_size = controls_bytes_size_plus_process_specific_size.checked_sub(controls_bytes_size.get()).ok_or(HasTooFewBytesForProcessSpecificData)?;
		
		let bmControls = entity_body.bytes(Self::ProcessTypeSize + sources_size + Self::OutputClusterSize + Self::ControlSizeSize, controls_bytes_size.get());
		let enable = (bmControls.get_unchecked_value_safe(0) & 0b1) != 0b0;
		
		let output_logical_audio_channel_cluster = return_ok_if_dead!(Version1LogicalAudioChannelCluster::parse(7 + p, device_connection, entity_body)?);
		Ok
		(
			Alive
			(
				Self
				{
					input_logical_audio_channel_clusters: InputLogicalAudioChannelClusters::parse(p, entity_body, 7, CouldNotAllocateMemoryForSources)?,
					
					enable,
					
					process_type: Self::parse_process_type(entity_body, bmControls, process_specific_size, p, &output_logical_audio_channel_cluster, sources_size, controls_bytes_size)?,
					
					output_logical_audio_channel_cluster,
					
					description: return_ok_if_dead!(device_connection.find_string(entity_body.u8(entity_body.len() - 1)).map_err(InvalidDescriptionString)?),
				}
			)
		)
	}
	
	const ProcessTypeSize: usize = 2;
	
	const OutputClusterSize: usize =
	{
		const NumberOfChannelsSize: usize = 1;
		const ChannelConfigSize: usize = 2;
		const ChannelNamesSize: usize = 1;
		NumberOfChannelsSize + ChannelConfigSize + ChannelNamesSize
	};
	
	const ControlSizeSize: usize = 1;
	
	const StringDescriptorSize: usize = 1;
	
	#[inline(always)]
	fn parse_process_type(entity_body: &[u8], bmControls: &[u8], process_specific_size: usize, p: usize, output_logical_audio_channel_cluster: &Version1LogicalAudioChannelCluster, sources_size: usize, controls_bytes_size: NonZeroUsize) -> Result<Version1ProcessType, Version1ProcessTypeParseError>
	{
		debug_assert_ne!(bmControls.len(), 0);
		
		let process_type_specific_bytes = entity_body.get_unchecked_range_safe(Self::ProcessTypeSize + sources_size + Self::OutputClusterSize + Self::ControlSizeSize + controls_bytes_size.get() + Self::StringDescriptorSize .. );
		debug_assert_eq!(process_type_specific_bytes.len(), process_specific_size);
		let process_type_code = entity_body.u16(entity_index::<DescriptorEntityMinimumLength>());
		Ok
		(
			match process_type_code
			{
				0x00 => Version1ProcessType::parse_undefined(bmControls, process_type_specific_bytes)?,
				
				0x01 => Version1ProcessType::parse_up_down_mix(bmControls, process_type_specific_bytes, p, output_logical_audio_channel_cluster)?,
				
				0x02 => Version1ProcessType::parse_dolby_pro_logic(bmControls, process_type_specific_bytes, p, output_logical_audio_channel_cluster)?,
				
				0x03 => Version1ProcessType::parse_three_dimensional_stereo_extended(bmControls, process_type_specific_bytes, p)?,
				
				0x04 => Version1ProcessType::parse_reverberation(bmControls, process_type_specific_bytes, p)?,
				
				0x05 => Version1ProcessType::parse_chorus(bmControls, process_type_specific_bytes, p)?,
				
				0x06 => Version1ProcessType::parse_dynamic_range_compressor(bmControls, process_type_specific_bytes, p)?,
				
				_ => Version1ProcessType::parse_unrecognized(bmControls, process_type_specific_bytes, process_type_code)?,
			}
		)
	}
}
