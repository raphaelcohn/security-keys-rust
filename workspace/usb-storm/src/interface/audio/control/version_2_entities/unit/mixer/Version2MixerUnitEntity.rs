// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// A mixer unit entity.
#[derive(Debug, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
#[allow(missing_docs)]
pub struct Version2MixerUnitEntity
{
	input_logical_audio_channel_clusters: InputLogicalAudioChannelClusters,
	
	output_logical_audio_channel_cluster: Version2LogicalAudioChannelCluster,
	
	controls_bit_map: Vec<u8>,
	
	cluster_control: Control,
	
	underflow_control: Control,
	
	overflow_control: Control,
	
	description: Option<LocalizedStrings>,
}

impl Entity for Version2MixerUnitEntity
{
	type EntityIdentifier = UnitEntityIdentifier;
	
	type ParseError = Version2EntityDescriptorParseError;
	
	#[inline(always)]
	fn cast_entity_identifier(value: EntityIdentifier) -> Self::EntityIdentifier
	{
		value
	}
	
	#[inline(always)]
	fn parse(entity_body: &[u8], device_connection: &DeviceConnection) -> Result<DeadOrAlive<Self>, Self::ParseError>
	{
		Ok(Self::parse_inner(entity_body, device_connection)?)
	}
}

impl DescribedEntity for Version2MixerUnitEntity
{
	#[inline(always)]
	fn description(&self) -> Option<&LocalizedStrings>
	{
		self.description.as_ref()
	}
}

impl Version2Entity for Version2MixerUnitEntity
{
}

impl UnitEntity for Version2MixerUnitEntity
{
}

impl MixerUnitEntity for Version2MixerUnitEntity
{
}

impl Version2MixerUnitEntity
{
	#[allow(missing_docs)]
	#[inline(always)]
	pub fn input_logical_audio_channel_clusters(&self) -> &InputLogicalAudioChannelClusters
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
	pub fn controls_bit_map(&self) -> &[u8]
	{
		&self.controls_bit_map
	}
	
	#[allow(missing_docs)]
	#[inline(always)]
	pub fn cluster_control(&self) -> Control
	{
		self.cluster_control
	}
	
	#[allow(missing_docs)]
	#[inline(always)]
	pub fn underflow_control(&self) -> Control
	{
		self.underflow_control
	}
	
	#[allow(missing_docs)]
	#[inline(always)]
	pub fn overflow_control(&self) -> Control
	{
		self.overflow_control
	}
	
	#[inline(always)]
	fn parse_inner(entity_body: &[u8], device_connection: &DeviceConnection) -> Result<DeadOrAlive<Self>, Version2MixerUnitEntityParseError>
	{
		use Version2MixerUnitEntityParseError::*;
		
		let p = parse_p::<DescriptorEntityMinimumLength>(entity_body);
		
		/// 13.
		const MinimumBLength: usize = Version2EntityDescriptors::MixerUnitMinimumBLength as usize;
		
		let N =
		{
			let bLength = DescriptorEntityMinimumLength + entity_body.len();
			
			// bLength = 13 + p + N
			// Thus N = (bLength - 13 - p)
			(bLength - MinimumBLength).checked_sub(p).ok_or(BLengthTooShort)?
		};
		
		let bmControls = entity_body.u8(entity_index_non_constant(11 + p + N));
		
		Ok
		(
			Alive
			(
				Self
				{
					input_logical_audio_channel_clusters: InputLogicalAudioChannelClusters::parse(p, entity_body, 5, CouldNotAllocateMemoryForSources)?,
					
					output_logical_audio_channel_cluster: return_ok_if_dead!(Version2LogicalAudioChannelCluster::parse_entity(5 + p, device_connection, entity_body).map_err(LogicalAudioChannelClusterParse)?),
					
					controls_bit_map: Vec::new_from(entity_body.bytes(entity_index_non_constant(11 + p), N)).map_err(CouldNotAllocateMemoryForControlsBitMap)?,
					
					cluster_control: Control::parse_u8(bmControls, 0, ClusterControlInvalid)?,
					
					underflow_control: Control::parse_u8(bmControls, 1, UnderflowControlInvalid)?,
					
					overflow_control: Control::parse_u8(bmControls, 2, OverflowControlInvalid)?,
					
					description: return_ok_if_dead!(device_connection.find_string(entity_body.u8(entity_index_non_constant(12 + p + N))).map_err(InvalidDescriptionString)?),
				}
			)
		)
	}
}
