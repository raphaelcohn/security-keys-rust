// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// An audio channel cluster.
#[derive(Debug, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
#[allow(missing_docs)]
pub enum Version2LogicalAudioChannelCluster
{
	RawData,

	Cluster(LogicalAudioChannelCluster<Version2LogicalAudioChannelSpatialLocation>),
}

impl Version2LogicalAudioChannelCluster
{
	#[inline(always)]
	pub(crate) fn parse_descriptor(channels_index: usize, device_connection: &DeviceConnection, descriptor_body: &[u8]) -> Result<DeadOrAlive<Self>, LogicalAudioChannelClusterParseError<Version2LogicalAudioChannelClusterParseError>>
	{
		Self::parse_generic(descriptor_index_non_constant(channels_index), device_connection, descriptor_body)
	}
	
	#[inline(always)]
	pub(super) fn parse_entity(channels_index: usize, device_connection: &DeviceConnection, entity_body: &[u8]) -> Result<DeadOrAlive<Self>, LogicalAudioChannelClusterParseError<Version2LogicalAudioChannelClusterParseError>>
	{
		Self::parse_generic(entity_index_non_constant(channels_index), device_connection, entity_body)
	}
	
	#[inline(always)]
	fn parse_generic(bytes_index: usize, device_connection: &DeviceConnection, bytes: &[u8]) -> Result<DeadOrAlive<Self>, LogicalAudioChannelClusterParseError<Version2LogicalAudioChannelClusterParseError>>
	{
		let number_of_logical_audio_channels = bytes.u8(bytes_index);
		let wChannelConfig = bytes.u32(entity_index_non_constant(bytes_index + 1));
		let first_logical_channel_name_string_identifier = bytes.u8(bytes_index + 3);
		
		Self::parse_inner(device_connection, number_of_logical_audio_channels, wChannelConfig, first_logical_channel_name_string_identifier)
	}
	
	const RawDataBit: u32 = 1 << 31;
	
	#[inline(always)]
	fn parse_inner(device_connection: &DeviceConnection, number_of_logical_audio_channels: u8, wChannelConfig: u32, first_logical_channel_name_string_identifier: u8) -> Result<DeadOrAlive<Self>, LogicalAudioChannelClusterParseError<Version2LogicalAudioChannelClusterParseError>>
	{
		if unlikely!(wChannelConfig & Self::RawDataBit != 0)
		{
			return Self::parse_raw_data(number_of_logical_audio_channels, wChannelConfig, first_logical_channel_name_string_identifier).map_err(LogicalAudioChannelClusterParseError::Specific)
		}
		
		let cluster = LogicalAudioChannelCluster::parse_inner(device_connection, number_of_logical_audio_channels, wChannelConfig, first_logical_channel_name_string_identifier)?;
		let cluster = return_ok_if_dead!(cluster);
		Ok(Alive(Version2LogicalAudioChannelCluster::Cluster(cluster)))
	}
	
	#[inline(always)]
	fn parse_raw_data(number_of_logical_audio_channels: u8, wChannelConfig: u32, first_logical_channel_name_string_identifier: u8) -> Result<DeadOrAlive<Self>, Version2LogicalAudioChannelClusterParseError>
	{
		use Version2LogicalAudioChannelClusterParseError::*;
		
		if unlikely!(wChannelConfig != Self::RawDataBit)
		{
			return Err(RawDataHasOtherBitsSet)
		}
		if unlikely!(number_of_logical_audio_channels != 0)
		{
			return Err(RawDataHasNonZeroNumberOfChannels)
		}
		if unlikely!(first_logical_channel_name_string_identifier != 0)
		{
			return Err(RawDataHasChannelNames)
		}
		Ok(Alive(Version2LogicalAudioChannelCluster::RawData))
	}
}
