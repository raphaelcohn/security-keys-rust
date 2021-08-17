// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// A logical audio channel cluster.
#[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
#[allow(missing_docs)]
pub struct LogicalAudioChannelCluster<LACSL: LogicalAudioChannelSpatialLocation>(WrappedIndexSet<LogicalAudioChannel<LACSL>>);

impl<LACSL: LogicalAudioChannelSpatialLocation> Deref for LogicalAudioChannelCluster<LACSL>
{
	type Target = WrappedIndexSet<LogicalAudioChannel<LACSL>>;
	
	#[inline(always)]
	fn deref(&self) -> &Self::Target
	{
		&self.0
	}
}

impl<LACSL: LogicalAudioChannelSpatialLocation> LogicalAudioChannelCluster<LACSL>
{
	#[allow(missing_docs)]
	#[inline(always)]
	pub fn contains_spatial_channel(&self, location: LACSL) -> bool
	{
		self.0.contains(&LogicalAudioChannel::Spatial(location))
	}
	
	#[inline(always)]
	pub(crate) fn parse_inner<E: error::Error>(string_finder: &StringFinder, number_of_logical_audio_channels: u8, channel_configuration: LACSL::Numeric, first_logical_channel_name_string_identifier: u8) -> Result<DeadOrAlive<Self>, LogicalAudioChannelClusterParseError<E>>
	{
		use LogicalAudioChannelClusterParseError::*;
		use LogicalAudioChannel::*;
		
		let mut logical_audio_channels = WrappedIndexSet::with_capacity(number_of_logical_audio_channels).map_err(CouldNotAllocateMemoryForLogicalAudioChannels)?;
		
		for channel_spatial_location in WrappedBitFlags::from_bits_unchecked(channel_configuration).iter()
		{
			let inserted = logical_audio_channels.insert(Spatial(channel_spatial_location));
			debug_assert!(inserted);
		}
		
		let spatial_logical_audio_channels_count = logical_audio_channels.len() as u8;
		if unlikely!(number_of_logical_audio_channels < spatial_logical_audio_channels_count)
		{
			return Err(NumberOfLogicalAudioChannelsIsLessThanNumberOfSpatialLogicalAudioChannels)
		}
		
		let non_spatial_channel_count = number_of_logical_audio_channels - spatial_logical_audio_channels_count;
		
		if first_logical_channel_name_string_identifier == 0
		{
			for index in 0 .. non_spatial_channel_count
			{
				let channel_index = spatial_logical_audio_channels_count + index;
				let inserted = logical_audio_channels.insert(Named { channel_index, name: None });
				debug_assert!(inserted);
			}
		}
		else
		{
			{
				let maximum_inclusive_string_identifier = (first_logical_channel_name_string_identifier as u16) + (non_spatial_channel_count as u16);
				if unlikely!(maximum_inclusive_string_identifier > (u8::MAX as u16))
				{
					return Err(NamedLogicalAudioChannelStringIdentifierGreaterThan255)
				}
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
