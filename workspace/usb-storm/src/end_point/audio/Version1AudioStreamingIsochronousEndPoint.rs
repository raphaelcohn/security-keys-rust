// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// Audio streaming isochronous end point.
#[derive(Debug, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
#[derive(Deserialize, Serialize)]
pub struct Version1AudioStreamingIsochronousEndPoint
{
	maximum_packets_only: bool,
	
	sampling_frequency_control: bool,
	
	pitch_control: bool,
	
	lock_delay: LockDelay,
}

impl Version1AudioStreamingIsochronousEndPoint
{
	#[allow(missing_docs)]
	#[inline(always)]
	pub const fn maximum_packets_only(&self) -> bool
	{
		self.maximum_packets_only
	}
	
	#[allow(missing_docs)]
	#[inline(always)]
	pub const fn sampling_frequency_control(&self) -> bool
	{
		self.sampling_frequency_control
	}
	
	#[allow(missing_docs)]
	#[inline(always)]
	pub const fn pitch_control(&self) -> bool
	{
		self.pitch_control
	}
	
	#[allow(missing_docs)]
	#[inline(always)]
	pub const fn lock_delay(&self) -> LockDelay
	{
		self.lock_delay
	}
	
	#[inline(always)]
	fn parse(bLength: u8, descriptor_body: &[u8]) -> Result<Self, Version1AudioStreamingIsochronousEndPointParseError>
	{
		use Version1AudioStreamingIsochronousEndPointParseError::*;
		
		if unlikely!(bLength < 7)
		{
			return Err(BLengthTooShort)
		}
		
		let bmAttributes = descriptor_body.u8(descriptor_index::<3>());
		Ok
		(
			Self
			{
				maximum_packets_only: (bmAttributes & 0b1000_0000) != 0,
				
				sampling_frequency_control: (bmAttributes & 0b0000_0001) != 0,
				
				pitch_control: (bmAttributes & 0b0000_0010) != 0,
				
				lock_delay:
				{
					let unit = descriptor_body.u8(descriptor_index::<4>());
					let delay = descriptor_body.u16(descriptor_index::<5>());
					LockDelay::parse(unit, delay, InvalidLockDelayUnit { unit })?
				}
			}
		)
	}
}
