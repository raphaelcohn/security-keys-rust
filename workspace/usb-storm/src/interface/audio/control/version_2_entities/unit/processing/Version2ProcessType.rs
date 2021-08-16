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
	fn parse_undefined(bmControls: u32, process_type_specific_bytes: &[u8]) -> Result<Self, Version2ProcessTypeParseError>
	{
		Ok
		(
			Version2ProcessType::Undefined
			{
				controls: bmControls,
			
				data: Vec::new_from(process_type_specific_bytes).map_err(Version2UndefinedProcessTypeParseError::CouldNotAllocateMemoryForData)?,
			}
		)
	}
	
	#[inline(always)]
	fn parse_up_down_mix(bmControls: u32, process_type_specific_bytes: &[u8], p: usize, output_logical_audio_channel_cluster: &Version2LogicalAudioChannelCluster) -> Result<Self, Version2ProcessTypeParseError>
	{
		use Version2UpDownMixProcessTypeParseError::*;
		
		validate_process_type_not_empty(process_type_specific_bytes, p, MustHaveAtLeastOneByteOfProcessSpecificData, MustHaveOnlyOneInputPin)?;
		
		Ok
		(
			Version2ProcessType::UpDownMix
			{
				mode_select_control: Control::parse_u32(bmControls, 1, ModeSelectControlInvalid)?,
				
				cluster_control: Control::parse_u32(bmControls, 2, ClusterControlInvalid)?,
			
				underflow_control: Control::parse_u32(bmControls, 3, UnderflowControlInvalid)?,
			
				overflow_control: Control::parse_u32(bmControls, 4, OverflowControlInvalid)?,
			
				modes: parse_process_type_modes
				(
					process_type_specific_bytes,
					output_logical_audio_channel_cluster,
					|mode| Ok(mode),
					CouldNotAllocateMemoryForModes,
					|mode, spatial_location| CanNotHaveThisModeAsASpatialChannelOutputIsAbsent { mode, spatial_location },
					|mode| HasDuplicateMode { mode }
				)?,
			}
		)
	}
	
	#[inline(always)]
	fn parse_dolby_pro_logic(bmControls: u32, process_type_specific_bytes: &[u8], p: usize, output_logical_audio_channel_cluster: &Version2LogicalAudioChannelCluster) -> Result<Self, Version2ProcessTypeParseError>
	{
		use Version2DolbyProLogicProcessTypeParseError::*;
		
		validate_process_type_not_empty(process_type_specific_bytes, p, MustHaveAtLeastOneByteOfProcessSpecificData, MustHaveOnlyOneInputPin)?;
		
		Ok
		(
			Version2ProcessType::DolbyProLogic
			{
				mode_select_control: Control::parse_u32(bmControls, 1, ModeSelectControlInvalid)?,
				
				cluster_control: Control::parse_u32(bmControls, 2, ClusterControlInvalid)?,
				
				underflow_control: Control::parse_u32(bmControls, 3, UnderflowControlInvalid)?,
				
				overflow_control: Control::parse_u32(bmControls, 4, OverflowControlInvalid)?,
				
				modes: parse_process_type_modes
				(
					process_type_specific_bytes,
					output_logical_audio_channel_cluster,
					|mode| DolbyProLogicMode::try_from(mode).map_err(CanNotHaveThisMode),
					CouldNotAllocateMemoryForModes,
					|mode, spatial_location| CanNotHaveThisModeAsASpatialChannelOutputIsAbsent { mode, spatial_location },
					|mode| HasDuplicateMode { mode }
				)?,
			}
		)
	}
	
	#[inline(always)]
	fn parse_stereo_extender(bmControls: u32, process_type_specific_bytes: &[u8], p: usize, output_logical_audio_channel_cluster: &Version2LogicalAudioChannelCluster) -> Result<Self, Version2ProcessTypeParseError>
	{
		use Version2StereoExtenderProcessTypeParseError::*;
		
		validate_process_type_empty(process_type_specific_bytes, p, MustNotHaveProcessSpecificBytes, MustHaveOnlyOneInputPin)?;
		
		Ok
		(
			Version2ProcessType::StereoExtender
			{
				width_control: Control::parse_u32(bmControls, 1, WidthControlInvalid)?,
				
				cluster_control: Control::parse_u32(bmControls, 1, ClusterControlInvalid)?,
				
				underflow_control: Control::parse_u32(bmControls, 1, UnderflowControlInvalid)?,
				
				overflow_control: Control::parse_u32(bmControls, 1, OverflowControlInvalid)?,
			}
		)
	}
	
	#[inline(always)]
	fn parse_unrecognized(bmControls: u32, process_type_specific_bytes: &[u8], process_type_code: u16) -> Result<Self, Version2ProcessTypeParseError>
	{
		Ok
		(
			Version2ProcessType::Unrecognized
			{
				controls: bmControls,
			
				data: Vec::new_from(process_type_specific_bytes).map_err(Version2UnrecognizedProcessTypeParseError::CouldNotAllocateMemoryForData)?,
			
				process_type_code: new_non_zero_u16(process_type_code),
			}
		)
	}
}
