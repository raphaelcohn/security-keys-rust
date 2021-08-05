// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// In a trully stupid design decision, the USB Implementors Forum redefined the endpoint descriptor to be a different size for Audio devices rather than use additional descriptors.
#[derive(Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EndPointAudioExtension
{
	synchronization_feedback_refresh_rate: u8,
	
	synchronization_address: u8,
}

impl EndPointAudioExtension
{
	#[allow(missing_docs)]
	#[inline(always)]
	pub const fn synchronization_feedback_refresh_rate(&self) -> u8
	{
		self.synchronization_feedback_refresh_rate
	}
	
	#[allow(missing_docs)]
	#[inline(always)]
	pub const fn synchronization_address(&self) -> u8
	{
		self.synchronization_feedback_refresh_rate
	}
}
