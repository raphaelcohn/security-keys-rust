// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// Process type.
#[derive(Debug, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub enum Version2ProcessType
{
	#[allow(missing_docs)]
	Undefined
	{
		controls: u32,
		
		data: Vec<u8>,
	},
	
	#[allow(missing_docs)]
	UpDownMix
	{
		mode_select_control: Control,
		
		cluster_control: Control,
		
		underflow_control: Control,
		
		overflow_control: Control,
		
		modes: WrappedIndexSet<WrappedBitFlags<Version2LogicalAudioChannelSpatialLocation>>,
	},
	
	#[allow(missing_docs)]
	DolbyProLogic
	{
		mode_select_control: Control,
		
		cluster_control: Control,
		
		underflow_control: Control,
		
		overflow_control: Control,
		
		/// Contains a maximum of 3 modes.
		modes: WrappedIndexSet<DolbyProLogicMode>,
	},
	
	#[allow(missing_docs)]
	StereoExtender
	{
		width_control: Control,
		
		cluster_control: Control,
		
		underflow_control: Control,
		
		overflow_control: Control,
	},
	
	#[allow(missing_docs)]
	Unrecognized
	{
		controls: u32,
		
		data: Vec<u8>,
		
		process_type_code: NonZeroU16,
	}
}

impl Version2ProcessType
{
	#[inline(always)]
	fn parse_undefined(_bmControls: u32, process_type_specific_bytes: &[u8]) -> Result<Self, Version2ProcessTypeParseError>
	{
		use Version2ProcessTypeParseError::*;
		
		Ok
		(
			Version2ProcessType::Unrecognized
			{
				controls: bmControls,
			
				data: Vec::new_from(process_type_specific_bytes).map_err(CouldNotAllocateMemoryForProcessTypeUndefinedData)?,
			
				process_type_code: new_non_zero_u16(process_type_code),
			}
		)
	}
	
	#[inline(always)]
	fn parse_up_down_mix(bmControls: u32, process_type_specific_bytes: &[u8], p: usize, output_logical_audio_channel_cluster: &Version2LogicalAudioChannelCluster) -> Result<Self, Version2ProcessTypeParseError>
	{
		use Version2ProcessTypeParseError::*;
		
		validate_process_type_not_empty(process_type_specific_bytes, p, UpDownMixProcessTypeMustHaveAtLeastOneByteOfProcessSpecificData, UpDownMixProcessTypeMustHaveOnlyOneInputPin)?;
		
		Ok
		(
			Version2ProcessType::UpDownMix
			{
				mode_select_control: Control::parse_u32(bmControls, 1, UpDownMixProceesingUnitModeSelectControlInvalid)?,
				
				cluster_control: Control::parse_u32(bmControls, 2, UpDownMixProceesingUnitClusterControlInvalid)?,
			
				underflow_control: Control::parse_u32(bmControls, 3, UpDownMixProceesingUnitUnderflowControlInvalid)?,
			
				overflow_control: Control::parse_u32(bmControls, 4, UpDownMixProceesingUnitOverflowControlInvalid)?,
			
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
	fn parse_dolby_pro_logic(bmControls: u32, process_type_specific_bytes: &[u8], p: usize, output_logical_audio_channel_cluster: &Version2LogicalAudioChannelCluster) -> Result<Self, Version2ProcessTypeParseError>
	{
		use Version2ProcessTypeParseError::*;
		
		validate_process_type_not_empty(process_type_specific_bytes, p, DolbyProLogicProcessTypeMustHaveAtLeastOneByteOfProcessSpecificData, DolbyProLogicProcessTypeMustHaveOnlyOneInputPin)?;
		
		Ok
		(
			Version2ProcessType::DolbyProLogic
			{
				mode_select_control: Control::parse_u32(bmControls, 1, DolbyProLogicProceesingUnitModeSelectControlInvalid)?,
				
				cluster_control: Control::parse_u32(bmControls, 2, DolbyProLogicProceesingUnitClusterControlInvalid)?,
				
				underflow_control: Control::parse_u32(bmControls, 3, DolbyProLogicProceesingUnitUnderflowControlInvalid)?,
				
				overflow_control: Control::parse_u32(bmControls, 4, DolbyProLogicProceesingUnitOverflowControlInvalid)?,
				
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
	fn parse_stereo_extender(bmControls: u32, process_type_specific_bytes: &[u8], p: usize, output_logical_audio_channel_cluster: &Version2LogicalAudioChannelCluster) -> Result<Self, Version2ProcessTypeParseError>
	{
		use Version2ProcessTypeParseError::*;
		
		validate_process_type_empty(process_type_specific_bytes, p, StereoExtenderProcessTypeMustNotHaveProcessTypeSpecificBytes, StereoExtenderProcessTypeMustHaveOnlyOneInputPin)?;
		
		Ok
		(
			Version2ProcessType::StereoExtender
			{
				width_control: Control::parse_u32(bmControls, 1, StereoExtenderProcessingUnitWidthControlInvalid)?,
				
				cluster_control: Control::parse_u32(bmControls, 1, StereoExtenderProcessingUnitClusterControlInvalid)?,
				
				underflow_control: Control::parse_u32(bmControls, 1, StereoExtenderProcessingUnitUnderflowControlInvalid)?,
				
				overflow_control: Control::parse_u32(bmControls, 1, StereoExtenderProcessingUnitOverflowControlInvalid)?,
			}
		)
	}
	
	#[inline(always)]
	fn parse_unrecognized(bmControls: u32, process_type_specific_bytes: &[u8], process_type_code: u16) -> Result<Self, Version2ProcessTypeParseError>
	{
		use Version2ProcessTypeParseError::*;
		
		Ok
		(
			Version2ProcessType::Unrecognized
			{
				controls: bmControls,
			
				data: Vec::new_from(process_type_specific_bytes).map_err(CouldNotAllocateMemoryForProcessTypeUnrecognizedData)?,
			
				process_type_code: new_non_zero_u16(process_type_code),
			}
		)
	}
}
