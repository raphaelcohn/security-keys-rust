// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// Version 1 logical audio channel cluster.
pub type Version1LogicalAudioChannelCluster = LogicalAudioChannelCluster<Version1LogicalAudioChannelSpatialLocation>;

impl Version1LogicalAudioChannelCluster
{
	#[inline(always)]
	pub(super) fn parse(channels_index: usize, device_connection: &DeviceConnection, entity_body: &[u8]) -> Result<DeadOrAlive<Self>, LogicalAudioChannelClusterParseError<InfallibleError>>
	{
		let number_of_logical_audio_channels = entity_body.u8(entity_index_non_constant(channels_index));
		let wChannelConfig = entity_body.u16(entity_index_non_constant(channels_index + 1));
		let first_logical_channel_name_string_identifier = entity_body.u8(entity_index_non_constant(channels_index + 3));
		
		Self::parse_inner(device_connection, number_of_logical_audio_channels, wChannelConfig, first_logical_channel_name_string_identifier)
	}
}
