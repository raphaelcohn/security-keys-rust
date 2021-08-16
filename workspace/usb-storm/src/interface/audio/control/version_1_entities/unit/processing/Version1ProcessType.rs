// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// Process type.
#[derive(Debug, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub enum Version1ProcessType
{
	#[allow(missing_docs)]
	Undefined(Vec<u8>),
	
	#[allow(missing_docs)]
	UpDownMix
	{
		mode_select: bool,
		
		modes: WrappedIndexSet<WrappedBitFlags<Version1LogicalAudioChannelSpatialLocation>>,
	},
	
	#[allow(missing_docs)]
	DolbyProLogic
	{
		mode_select: bool,
	
		/// Contains a maximum of 3 modes.
		modes: WrappedIndexSet<DolbyProLogicMode>,
	},
	
	#[allow(missing_docs)]
	ThreeDimensionalStereoExtender
	{
		spaciousness: bool,
	},
	
	#[allow(missing_docs)]
	Reverberation
	{
		type_: bool,
		
		level: bool,
		
		time: bool,
		
		delay_feedback: bool,
	},
	
	#[allow(missing_docs)]
	Chrous
	{
		level: bool,
		
		modulation_rate: bool,
		
		modulation_depth: bool,
	},
	
	#[allow(missing_docs)]
	DynamicRangeCompressor
	{
		compression_ratio: bool,
		
		maximum_amplitude: bool,
		
		threshold: bool,
		
		attack_time: bool,
		
		release_time: bool,
	},
	
	#[allow(missing_docs)]
	Unrecognized
	{
		controls: Vec<u8>,
		
		data: Vec<u8>,
		
		process_type_code: NonZeroU16,
	}
}

impl Version1ProcessType
{
	#[inline(always)]
	fn parse_undefined(_bmControls: &[u8], process_type_specific_bytes: &[u8]) -> Result<Self, Version1ProcessTypeParseError>
	{
		let data = Vec::new_from(process_type_specific_bytes).map_err(Version1ProcessTypeParseError::CouldNotAllocateMemoryForProcessTypeUndefinedData)?;
		Ok(Version1ProcessType::Undefined(data))
	}
	
	#[inline(always)]
	fn parse_up_down_mix(bmControls: &[u8], process_type_specific_bytes: &[u8], p: usize, output_logical_audio_channel_cluster: &Version1LogicalAudioChannelCluster) -> Result<Self, Version1ProcessTypeParseError>
	{
		use Version1ProcessTypeParseError::*;
		
		validate_process_type_not_empty(process_type_specific_bytes, p, UpDownMixProcessTypeMustHaveAtLeastOneByteOfProcessSpecificData, UpDownMixProcessTypeMustHaveOnlyOneInputPin)?;
		
		let byte = bmControls.get_unchecked_value_safe(0);
		Ok
		(
			Version1ProcessType::UpDownMix
			{
				mode_select: Self::parse_control(byte, 1),
				
				modes: parse_process_type_modes
				(
					process_type_specific_bytes,
					output_logical_audio_channel_cluster,
					|mode| Ok(mode),
					CouldNotAllocateMemoryForUpDownMixProcessTypeModes,
					|mode, spatial_location| UpDownMixProcessTypeCanNotHaveThisModeAsASpatialChannelOutputIsAbsent { mode, spatial_location },
					|mode| UpDownMixProcessTypeHasDuplicateMode { mode }
				)?,
			}
		)
	}
	
	#[inline(always)]
	fn parse_dolby_pro_logic(bmControls: &[u8], process_type_specific_bytes: &[u8], p: usize, output_logical_audio_channel_cluster: &Version1LogicalAudioChannelCluster) -> Result<Self, Version1ProcessTypeParseError>
	{
		use Version1ProcessTypeParseError::*;
		
		validate_process_type_not_empty(process_type_specific_bytes, p, DolbyProLogicProcessTypeMustHaveAtLeastOneByteOfProcessSpecificData, DolbyProLogicProcessTypeMustHaveOnlyOneInputPin)?;
		
		let byte = bmControls.get_unchecked_value_safe(0);
		Ok
		(
			Version1ProcessType::DolbyProLogic
			{
				mode_select: Self::parse_control(byte, 1),
			
				modes: parse_process_type_modes
				(
					process_type_specific_bytes,
					output_logical_audio_channel_cluster,
					|mode| DolbyProLogicMode::try_from(mode).map_err(DolbyProLogicProcessTypeCanNotHaveThisMode),
					CouldNotAllocateMemoryForDolbyProLogicProcessTypeModes,
					|mode, spatial_location| DolbyProLogicProcessTypeCanNotHaveThisModeAsASpatialChannelOutputIsAbsent { mode, spatial_location },
					|mode| DolbyProLogicProcessTypeHasDuplicateMode { mode }
				)?,
			}
		)
	}
	
	#[inline(always)]
	fn parse_three_dimensional_stereo_extended(bmControls: &[u8], process_type_specific_bytes: &[u8], p: usize, output_logical_audio_channel_cluster: &Version1LogicalAudioChannelCluster) -> Result<Self, Version1ProcessTypeParseError>
	{
		use Version1ProcessTypeParseError::*;
		
		validate_process_type_empty(process_type_specific_bytes, p, ThreeDimensionalStereoExtendedProcessTypeMustNotHaveProcessTypeSpecificBytes, ThreeDimensionalStereoExtendedProcessTypeMustHaveOnlyOneInputPin)?;
		
		let byte = bmControls.get_unchecked_value_safe(0);
		Ok
		(
			Version1ProcessType::ThreeDimensionalStereoExtender
			{
				spaciousness: Self::parse_control(byte, 1),
			}
		)
	}
	
	#[inline(always)]
	fn parse_reverberation(bmControls: &[u8], process_type_specific_bytes: &[u8], p: usize) -> Result<Self, Version1ProcessTypeParseError>
	{
		use Version1ProcessTypeParseError::*;
		
		validate_process_type_empty(process_type_specific_bytes, p, ReverberationProcessTypeMustNotHaveProcessTypeSpecificBytes, ReverberationProcessTypeMustHaveOnlyOneInputPin)?;
		
		let byte = bmControls.get_unchecked_value_safe(0);
		Ok
		(
			Version1ProcessType::Reverberation
			{
				type_: Self::parse_control(byte, 1),
				
				level: Self::parse_control(byte, 2),
				
				time: Self::parse_control(byte, 3),
				
				delay_feedback: Self::parse_control(byte, 4),
			}
		)
	}
	
	#[inline(always)]
	fn parse_chorus(bmControls: &[u8], process_type_specific_bytes: &[u8], p: usize) -> Result<Self, Version1ProcessTypeParseError>
	{
		use Version1ProcessTypeParseError::*;
		
		validate_process_type_empty(process_type_specific_bytes, p, ChorusProcessTypeMustNotHaveProcessTypeSpecificBytes, ChorusProcessTypeMustHaveOnlyOneInputPin)?;
				
		let byte = bmControls.get_unchecked_value_safe(0);
		Ok
		(
			Version1ProcessType::Chrous
			{
				level: Self::parse_control(byte, 1),
				
				modulation_rate: Self::parse_control(byte, 2),
				
				modulation_depth: Self::parse_control(byte, 3),
			}
		)
	}
	
	#[inline(always)]
	fn parse_dynamic_range_compressor(bmControls: &[u8], process_type_specific_bytes: &[u8], p: usize) -> Result<Self, Version1ProcessTypeParseError>
	{
		use Version1ProcessTypeParseError::*;
		
		validate_process_type_empty(process_type_specific_bytes, p, DynamicRangeCompressorProcessTypeMustNotHaveProcessTypeSpecificBytes, DynamicRangeCompressorProcessTypeMustHaveOnlyOneInputPin)?;
		
		let byte = bmControls.get_unchecked_value_safe(0);
		Ok
		(
			Version1ProcessType::DynamicRangeCompressor
			{
				compression_ratio: Self::parse_control(byte, 1),
				
				maximum_amplitude: Self::parse_control(byte, 2),
				
				threshold: Self::parse_control(byte, 3),
				
				attack_time: Self::parse_control(byte, 4),
				
				release_time: Self::parse_control(byte, 5),
			}
		)
	}
	
	#[inline(always)]
	fn parse_unrecognized(bmControls: &[u8], process_type_specific_bytes: &[u8], process_type_code: u16) -> Result<Self, Version1ProcessTypeParseError>
	{
		use Version1ProcessTypeParseError::*;
		Ok
		(
			Version1ProcessType::Unrecognized
			{
				controls: Vec::new_from(bmControls).map_err(CouldNotAllocateMemoryForProcessTypeUnrecognizedControls)?,
			
				data: Vec::new_from(process_type_specific_bytes).map_err(CouldNotAllocateMemoryForProcessTypeUnrecognizedData)?,
			
				process_type_code: new_non_zero_u16(process_type_code),
			}
		)
	}
	
	#[inline(always)]
	fn parse_control(byte: u8, control_index: u8) -> bool
	{
		debug_assert_ne!(control_index, 0, "enable control is generic to all process types");
		
		(byte & (1 << control_index)) != 0
	}
}
