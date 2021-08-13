// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// Channel controls by channel number.
#[derive(Debug, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
#[repr(transparent)]
pub struct ChannelControlsByChannelNumber<Controls>(Vec<Controls>);

impl<Controls> ChannelControlsByChannelNumber<Controls>
{
	#[allow(missing_docs)]
	#[inline(always)]
	pub fn number_of_logical_channels(&self) -> usize
	{
		let length = self.0.len();
		if unlikely!(length == 0)
		{
			0
		}
		else
		{
			length - 1
		}
	}
	
	#[allow(missing_docs)]
	#[inline(always)]
	pub fn master_channel_controls(&self) -> Option<&Controls>
	{
		self.0.get(0)
	}
	
	#[allow(missing_docs)]
	#[inline(always)]
	pub fn logical_channel_controls(&self, logical_audio_channel_number: LogicalAudioChannelNumber) -> Option<&Controls>
	{
		let index = logical_audio_channel_number.get() as usize;
		self.0.get(index)
	}
}
