// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


#[derive(Debug, Clone, Eq, PartialEq)]
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub enum LogicalAudioChannel
{
	/// Spatial.
	Spatial(LogicalAudioChannelSpatialLocation),
	
	/// Named.
	Named
	{
		/// Unnamed (channel_index up to to a maximum of 254, but does not necessarily start from 0; starts from spatial_logical_audio_channels_count).
		channel_index: u8,
		
		name: Option<LocalizedStrings>,
	},
}
