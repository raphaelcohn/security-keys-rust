// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// A feature unit entity.
#[derive(Debug, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
#[allow(missing_docs)]
pub struct Version2ExtensionUnitEntity
{
	input_logical_audio_channel_clusters: InputLogicalAudioChannelClusters,
	
	output_logical_audio_channel_cluster: Version2LogicalAudioChannelCluster,
	
	enable_control: Control,
	
	cluster_control: Control,
	
	overflow_control: Control,
	
	underflow_control: Control,
	
	extension_code: u16,
	
	description: Option<LocalizedStrings>,
}

impl Entity for Version2ExtensionUnitEntity
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

impl UnitEntity for Version2ExtensionUnitEntity
{
}

impl Version2ExtensionUnitEntity
{
	#[allow(missing_docs)]
	#[inline(always)]
	pub fn input_logical_audio_channel_cluster(&self) -> &InputLogicalAudioChannelClusters
	{
		&self.input_logical_audio_channel_clusters
	}
	
	#[allow(missing_docs)]
	#[inline(always)]
	pub fn output_logical_audio_channel_cluster(&self) -> &Version2LogicalAudioChannelCluster
	{
		&self.output_logical_audio_channel_cluster
	}
	
	#[allow(missing_docs)]
	#[inline(always)]
	pub const fn enable_control(&self) -> Control
	{
		self.enable_control
	}
	
	#[allow(missing_docs)]
	#[inline(always)]
	pub const fn extension_code(&self) -> u16
	{
		self.extension_code
	}
	
	#[allow(missing_docs)]
	#[inline(always)]
	pub const fn description(&self) -> Option<&LocalizedStrings>
	{
		self.description.as_ref()
	}
	
	#[inline(always)]
	fn parse_inner(entity_body: &[u8], string_finder: &StringFinder) -> Result<DeadOrAlive<Self>, Version2ExtensionUnitEntityParseError>
	{
		use Version2ExtensionUnitEntityParseError::*;
		
		let p =
		{
			const ExtensionCodeSize: usize = 2;
			const PIndex: usize = DescriptorEntityMinimumLength + ExtensionCodeSize;
			parse_p::<PIndex>(entity_body)
		};
		
		let x = (Version2EntityDescriptors::ExtensionUnitMinimumBLength as usize) + p - DescriptorEntityMinimumLength;
		if unlikely!(x != entity_body.len())
		{
			Err(PIsTooLarge)?
		}
		
		let bmControls = entity_body.u8(entity_index_non_constant(14 + p));
		
		Ok
		(
			Alive
			(
				Self
				{
					input_logical_audio_channel_clusters: InputLogicalAudioChannelClusters::parse(p, entity_body, 7, CouldNotAllocateMemoryForSources)?,
					
					output_logical_audio_channel_cluster: return_ok_if_dead!(Version2LogicalAudioChannelCluster::parse(8 + p, string_finder, entity_body).map_err(LogicalAudioChannelClusterParse)?),
					
					enable_control: Control::parse_u8(bmControls, 0, EnableControlInvalid)?,
					
					cluster_control: Control::parse_u8(bmControls, 0, ClusterControlInvalid)?,
					
					underflow_control: Control::parse_u8(bmControls, 0, UnderflowControlInvalid)?,
					
					overflow_control: Control::parse_u8(bmControls, 0, OverflowControlInvalid)?,
					
					extension_code: entity_body.u16(entity_index::<4>()),
					
					description: return_ok_if_dead!(string_finder.find_string(entity_body.u8(entity_index_non_constant(15 + p))).map_err(InvalidDescriptionString)?),
				}
			)
		)
	}
	
}
