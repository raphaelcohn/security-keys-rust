// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// An input terminal entity.
#[derive(Debug, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Version1ExtensionUnitEntity
{
	input_logical_audio_channel_clusters: InputLogicalAudioChannelClusters,
	
	enable: bool,
	
	controls_bit_map: Vec<u8>,
	
	extension_code: u16,
	
	description: Option<LocalizedStrings>,
}

impl Entity for Version1ExtensionUnitEntity
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
			const PIndex: usize = DescriptorEntityMinimumLength + ExtensionCodeSize;
			parse_p::<PIndex>(entity_body)
		};
		
		const ExtensionCodeSize: usize = 2;
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
			let control_size_index = DescriptorEntityMinimumLength + ExtensionCodeSize + sources_size + OutputClusterSize;
			if unlikely!(entity_index_non_constant(control_size_index) >= entity_body.len())
			{
				return Err(ExtensionUnitPIsTooLarge);
			}
			parse_control_size(entity_body, control_size_index, ExtensionUnitControlSizeIsZero)?
		};
		
		if unlikely!(entity_body.len() == ExtensionCodeSize + sources_size + OutputClusterSize + ControlSizeSize + controls_bytes_size.get() + StringDescriptorSize)
		{
			return Err(ExtensionUnitTooShort)
		}
		
		let bmControls = entity_body.bytes(ExtensionCodeSize + sources_size + OutputClusterSize + ControlSizeSize, controls_bytes_size.get());
		let enable = (bmControls.get_unchecked_value_safe(0) & 0b1) != 0b0;
		
		Ok
		(
			Alive
			(
				Self
				{
					input_logical_audio_channel_clusters: InputLogicalAudioChannelClusters::version_1_parse(p, entity_body, 7)?,
					
					enable,
					
					controls_bit_map: Vec::new_from(bmControls).map_err(CouldNotAllocateMemoryForExtensionUnitControlsBitMap)?,
					
					extension_code: entity_body.u16(entity_index::<4>()),
					
					description: return_ok_if_dead!(string_finder.find_string(entity_body.u8(entity_body.len() - 1)).map_err(InvalidDescriptionString)?),
				}
			)
		)
	}
}

impl UnitEntity for Version1ExtensionUnitEntity
{
}

impl Version1ExtensionUnitEntity
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
	pub const fn extension_code(&self) -> u16
	{
		self.extension_code
	}
	
	#[allow(missing_docs)]
	#[inline(always)]
	pub const fn input_logical_audio_channel_clusters(&self) -> &InputLogicalAudioChannelClusters
	{
		&self.input_logical_audio_channel_clusters
	}
}
