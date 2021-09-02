// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// Audio streaming isochronous end point.
#[derive(Debug, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
#[derive(Deserialize, Serialize)]
pub struct Version2AudioStreamingIsochronousEndPoint
{
	maximum_packets_only: bool,
	
	pitch_control: Control,
	
	data_overrun_control: Control,
	
	data_underrun_control: Control,
	
	lock_delay: LockDelay,
}

impl Version2AudioStreamingIsochronousEndPoint
{
	#[allow(missing_docs)]
	#[inline(always)]
	pub const fn maximum_packets_only(&self) -> bool
	{
		self.maximum_packets_only
	}
	
	#[allow(missing_docs)]
	#[inline(always)]
	pub const fn pitch_control(&self) -> Control
	{
		self.pitch_control
	}
	
	#[allow(missing_docs)]
	#[inline(always)]
	pub const fn data_overrun_control(&self) -> Control
	{
		self.data_overrun_control
	}
	
	#[allow(missing_docs)]
	#[inline(always)]
	pub const fn data_underrun_control(&self) -> Control
	{
		self.data_underrun_control
	}
	
	#[allow(missing_docs)]
	#[inline(always)]
	pub const fn lock_delay(&self) -> LockDelay
	{
		self.lock_delay
	}
	
	#[inline(always)]
	fn parse(bLength: u8, descriptor_body: &[u8]) -> Result<Self, Version2AudioStreamingIsochronousEndPointParseError>
	{
		use Version2AudioStreamingIsochronousEndPointParseError::*;
		
		if unlikely!(bLength < 8)
		{
			return Err(BLengthTooShort)
		}
		
		let bmControls = descriptor_body.u8(descriptor_index::<4>());
		Ok
		(
			Self
			{
				maximum_packets_only:
				{
					let bmAttributes = descriptor_body.u8(descriptor_index::<3>());
					(bmAttributes & 0b1000_0000) != 0
				},
				
				pitch_control: Control::parse_u8(bmControls, 0, PitchControlInvalid)?,
				
				data_overrun_control: Control::parse_u8(bmControls, 1, DataOverrunControlInvalid)?,
				
				data_underrun_control: Control::parse_u8(bmControls, 2, DataUnderrunControlInvalid)?,
				
				lock_delay:
				{
					let unit = descriptor_body.u8(descriptor_index::<5>());
					let delay = descriptor_body.u16(descriptor_index::<6>());
					LockDelay::parse(unit, delay, InvalidLockDelayUnit { unit })?
				}
			}
		)
	}
}
