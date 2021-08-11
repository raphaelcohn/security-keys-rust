// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// An audio channel cluster.
#[derive(Debug, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
#[allow(missing_docs)]
pub struct LogicalAudioChannelCluster(IndexSet<LogicalAudioChannel>);

impl Deref for LogicalAudioChannelCluster
{
	type Target = IndexSet<LogicalAudioChannel>;
	
	#[inline(always)]
	fn deref(&self) -> &Self::Target
	{
		&self.0
	}
}

impl LogicalAudioChannelCluster
{
	#[allow(missing_docs)]
	#[inline(always)]
	fn has_left_and_right(&self) -> bool
	{
		use LogicalAudioChannelSpatialLocation::*;
		
		self.contains_spatial_channel(LeftFront) && self.contains_spatial_channel(RightFront)
	}
	
	#[allow(missing_docs)]
	#[inline(always)]
	fn contains_spatial_channel(&self, location: LogicalAudioChannelSpatialLocation) -> bool
	{
		self.0.contains(LogicalAudioChannel::Spatial(location))
	}
	
	#[inline(always)]
	fn parse(channels_index: usize, string_finder: &StringFinder, entity_body: &[u8]) -> Result<DeadOrAlive<Self>, LogicalAudioChannelClusterParseError>
	{
		let number_of_logical_audio_channels = entity_body.u8_unadjusted(adjusted_index_non_constant(channels_index));
		let wChannelConfig = entity_body.u16_unadjusted(adjusted_index_non_constant(channels_index + 1));
		let first_logical_channel_name_string_identifier = entity_body.u8_unadjusted(adjusted_index_non_constant(channels_index + 3));
		
		Self::parse_inner(string_finder, number_of_logical_audio_channels, wChannelConfig, first_logical_channel_name_string_identifier)
	}
	
	#[inline(always)]
	fn parse_inner(string_finder: &StringFinder, number_of_logical_audio_channels: u8, wChannelConfig: u16, first_logical_channel_name_string_identifier: u8) -> Result<DeadOrAlive<Self>, LogicalAudioChannelClusterParseError>
	{
		use LogicalAudioChannelClusterParseError::*;
		use LogicalAudioChannel::*;
		
		let mut logical_audio_channels = IndexSet::with_capacity(number_of_logical_audio_channels as usize);
		
		let channel_spatial_locations = unsafe { BitFlags::from_bits_unchecked(wChannelConfig) };
		for channel_spatial_location in channel_spatial_locations.iter()
		{
			let inserted = logical_audio_channels.insert(Spatial(channel_spatial_location));
			debug_assert!(inserted);
		}
		
		let spatial_logical_audio_channels_count =
		{
			const BitsInAByte: usize = 8;
			const BitsInAnU16: usize = BitsInAByte * size_of::<u16>();
			let spatial_logical_audio_channels_count = logical_audio_channels.len();
			debug_assert!(spatial_logical_audio_channels_count < BitsInAnU16);
			spatial_logical_audio_channels_count as u8
		};
		
		if unlikely!(number_of_logical_audio_channels < spatial_logical_audio_channels_count)
		{
			return Err(NumberOfLogicalAudioChannelsIsLessThanNumberOfSpatialLogicalAudioChannels)
		}
		
		let non_spatial_channel_count = number_of_logical_audio_channels - spatial_logical_audio_channels_count;
		if first_logical_channel_name_string_identifier == 0
		{
			for index in 0 .. non_spatial_channel_count
			{
				let channel_index = spatial_logical_audio_channels_count + spatial_logical_audio_channels_count;
				let inserted = logical_audio_channels.insert(Named { channel_index, name: None });
				debug_assert!(inserted);
			}
		}
		else
		{
			let maximum_inclusive_string_identifier = (first_logical_channel_name_string_identifier as u16) + (non_spatial_channel_count as u16);
			if unlikely!(maximum_inclusive_string_identifier > (u8::MAX as u16))
			{
				return Err(NamedLogicalAudioChannelStringIdentifierGreaterThan255)
			}
			
			for index in 0 .. non_spatial_channel_count
			{
				let channel_index = spatial_logical_audio_channels_count + spatial_logical_audio_channels_count;
				let string_descriptor_index = new_non_zero_u8(first_logical_channel_name_string_identifier + index);
				let channel_name = return_ok_if_dead!(string_finder.find_string_non_zero(string_descriptor_index).map_err(|cause| ChannelNameString { cause, channel_index })?);
				let inserted = logical_audio_channels.insert(Named { channel_index, name: Some(channel_name) });
				debug_assert!(inserted);
			}
		}
		
		Ok(Alive(Self(logical_audio_channels)))
	}
}
