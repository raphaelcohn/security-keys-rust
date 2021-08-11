// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// Process type.
#[derive(Debug, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
#[allow(missing_docs)]
pub enum ProcessType
{
	Undefined(Vec<u8>),
	
	UpDownMix
	{
		mode_select: bool,
		
		modes: IndexSet<BitFlags<LogicalAudioChannelSpatialLocation>>,
	},
	
	DolbyProLogic
	{
		mode_select: bool,
	
		/// Contains a maximum of 3 modes.
		modes: IndexSet<DolbyProLogicMode>,
	},
	
	ThreeDimensionalStereoExtender
	{
		spaciousness: bool,
	},
	
	Reverberation
	{
		type_: bool,
		
		level: bool,
		
		time: bool,
		
		delay_feedback: bool,
	},
	
	Chrous
	{
		level: bool,
		
		modulation_rate: bool,
		
		modulation_depth: bool,
	},
	
	DynamicRangeCompressor
	{
		compression_ratio: bool,
		
		maximum_amplitude: bool,
		
		threshold: bool,
		
		attack_time: bool,
		
		release_time: bool,
	},
	
	Unrecognized
	{
		controls: Vec<u8>,
		
		data: Vec<u8>,
		
		process_type_code: NonZeroU16,
	}
}

impl ProcessType
{
	#[inline(always)]
	fn parse_undefined(_bmControls: &[u8], process_type_specific_bytes: &[u8]) -> Result<Self, Version1EntityDescriptorParseError>
	{
		let data = Vec::new_from(process_type_specific_bytes).map_err(Version1EntityDescriptorParseError::CouldNotAllocateMemoryForProcessTypeUndefinedData)?;
		Ok(ProcessType::Undefined(data))
	}
	
	#[inline(always)]
	fn parse_up_down_mix(bmControls: &[u8], process_type_specific_bytes: &[u8], p: usize) -> Result<Self, Version1EntityDescriptorParseError>
	{
		use Version1EntityDescriptorParseError::*;
		if unlikely!(p != 1)
		{
			return Err(UpDownMixProcessTypeMustHaveOnlyOneInputPin)
		}
		
		if process_type_specific_bytes.is_empty()
		{
			return Err(UpDownMixProcessTypeMustHaveAtLeastOneByteOfProcessSpecificData)
		}
		
		let bNrModes = process_type_specific_bytes.u8_unadjusted(0) as usize;
		
		let mut modes = IndexSet::with_capacity();
		for mode_index in 0 .. bNrModes
		{
			let mode = unsafe { BitFlags::from_bits_unchecked(process_type_specific_bytes.u16_unadjusted(1 + (mode_index * 2))) };
			for spatial_location in mode.into().iter()
			{
				if unlikely!(!output_logical_audio_channel_cluster.contains_spatial_channel())
				{
					return Err(UpDownMixProcessTypeCanNotHaveThisModeAsASpatialChannelOutputIsAbsent { mode, spatial_location })
				}
			}
			
			let inserted = modes.insert(mode);
			if unlikely!(!inserted)
			{
				return Err(UpDownMixProcessTypeHasDuplicateMode { mode })
			}
		}
		
		let byte = bmControls.get_unchecked_value_safe(0);
		Ok
		(
			ProcessType::UpDownMix
			{
				mode_select: (byte & 0b0000_0010) != 0,
			
				modes,
			}
		)
	}
	
	#[inline(always)]
	fn parse_dolby_pro_logic(bmControls: &[u8], process_type_specific_bytes: &[u8], p: usize, output_logical_audio_channel_cluster: &LogicalAudioChannelCluster) -> Result<Self, Version1EntityDescriptorParseError>
	{
		use Version1EntityDescriptorParseError::*;
		if unlikely!(p != 1)
		{
			return Err(DolbyProLogicProcessTypeMustHaveOnlyOneInputPin)
		}
		
		if process_type_specific_bytes.is_empty()
		{
			return Err(DolbyProLogicProcessTypeMustHaveAtLeastOneByteOfProcessSpecificData)
		}
		
		let bNrModes = process_type_specific_bytes.u8_unadjusted(0) as usize;
		const MaximumNumberOfModes: usize = 3;
		if unlikely!(bNrModes > MaximumNumberOfModes)
		{
			return Err(DolbyProLogicProcessTypeCanNotHaveMoreThanThreeModes)
		}
		
		let mut modes = IndexSet::with_capacity();
		for mode_index in 0 .. bNrModes
		{
			use DolbyProLogicMode::*;
			let mode = match process_type_specific_bytes.u16_unadjusted(1 + (mode_index * 2))
			{
				0x0007 => LeftRightCentre,
				
				0x0103 => LeftRightSurround,
				
				0x0107 => LeftRightCentreSurround,
				
				mode @ _ => return Err(DolbyProLogicProcessTypeCanNotHaveThisMode { mode })
			};
			for spatial_location in mode.into().iter()
			{
				if unlikely!(!output_logical_audio_channel_cluster.contains_spatial_channel())
				{
					return Err(DolbyProLogicProcessTypeCanNotHaveThisModeAsASpatialChannelOutputIsAbsent { mode, spatial_location })
				}
			}
			
			let inserted = modes.insert(mode);
			if unlikely!(!inserted)
			{
				return Err(DolbyProLogicProcessTypeHasDuplicateMode { mode })
			}
		}
		
		let byte = bmControls.get_unchecked_value_safe(0);
		Ok
		(
			ProcessType::DolbyProLogic
			{
				mode_select: (byte & 0b0000_0010) != 0,
			
				modes,
			}
		)
	}
	
	#[inline(always)]
	fn parse_three_dimensional_stereo_extended(bmControls: &[u8], process_type_specific_bytes: &[u8], p: usize, output_logical_audio_channel_cluster: &LogicalAudioChannelCluster) -> Result<Self, Version1EntityDescriptorParseError>
	{
		use Version1EntityDescriptorParseError::*;
		if unlikely!(p != 1)
		{
			return Err(ThreeDimensionalStereoExtendedProcessTypeMustHaveOnlyOneInputPin)
		}
		
		if unlikely!(!output_logical_audio_channel_cluster.has_left_and_right())
		{
			return Err(ThreeDimensionalStereoExtendedProcessTypeMustHaveLeftAndRightSpatialChannels)
		}
		
		let byte = bmControls.get_unchecked_value_safe(0);
		Ok
		(
			ProcessType::ThreeDimensionalStereoExtender
			{
				spaciousness: (byte & 0b0000_0010) != 0,
			}
		)
	}
	
	#[inline(always)]
	fn parse_reverberation(bmControls: &[u8], process_type_specific_bytes: &[u8], p: usize) -> Result<Self, Version1EntityDescriptorParseError>
	{
		if unlikely!(p != 1)
		{
			return Err(Version1EntityDescriptorParseError::ReverberationProcessTypeMustHaveOnlyOneInputPin)
		}
		
		let byte = bmControls.get_unchecked_value_safe(0);
		Ok
		(
			ProcessType::Reverberation
			{
				type_: (byte & 0b0000_0010) != 0,
				
				level: (byte & 0b0000_0100) != 0,
				
				time: (byte & 0b0000_1000) != 0,
				
				delay_feedback: (byte & 0b0001_0000) != 0,
			}
		)
	}
	
	#[inline(always)]
	fn parse_chorus(bmControls: &[u8], process_type_specific_bytes: &[u8], p: usize) -> Result<Self, Version1EntityDescriptorParseError>
	{
		if unlikely!(p != 1)
		{
			return Err(Version1EntityDescriptorParseError::ChorusProcessTypeMustHaveOnlyOneInputPin)
		}
		
		let byte = bmControls.get_unchecked_value_safe(0);
		Ok
		(
			ProcessType::Chrous
			{
				level: (byte & 0b0000_0010) != 0,
				
				modulation_rate: (byte & 0b0000_0100) != 0,
				
				modulation_depth: (byte & 0b0000_1000) != 0,
			}
		)
	}
	
	#[inline(always)]
	fn parse_dynamic_range_compressor(bmControls: &[u8], process_type_specific_bytes: &[u8], p: usize) -> Result<Self, Version1EntityDescriptorParseError>
	{
		if unlikely!(p != 1)
		{
			return Err(Version1EntityDescriptorParseError::DynamicRangeCompressorProcessTypeMustHaveOnlyOneInputPin)
		}
		
		let byte = bmControls.get_unchecked_value_safe(0);
		Ok
		(
			ProcessType::DynamicRangeCompressor
			{
				compression_ratio: (byte & 0b0000_0010) != 0,
				
				maximum_amplitude: (byte & 0b0000_0100) != 0,
				
				threshold: (byte & 0b0000_1000) != 0,
				
				attack_time: (byte & 0b0001_0000) != 0,
				
				release_time: (byte & 0b0010_0000) != 0,
			}
		)
	}
	
	#[inline(always)]
	fn parse_unrecognized(bmControls: &[u8], process_type_specific_bytes: &[u8], process_type_code: u16) -> Result<Self, Version1EntityDescriptorParseError>
	{
		use Version1EntityDescriptorParseError::*;
		Ok
		(
			ProcessType::Unrecognized
			{
				controls: Vec::new_from(bmControls).map_err(CouldNotAllocateMemoryForProcessTypeUnrecognizedControls)?,
			
				data: Vec::new_from(process_type_specific_bytes).map_err(CouldNotAllocateMemoryForProcessTypeUnrecognizedData)?,
			
				process_type_code: new_non_zero_u16(process_type_code),
			}
		)
	}
}
