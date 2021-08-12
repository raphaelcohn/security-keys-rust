// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// SuperSpeed.
#[derive(Debug, Copy, Clone, Eq, PartialEq, PartialOrd, Ord, Hash)]
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SuperSpeedDeviceCapability
{
	supports_latency_tolerant_messages: bool,

	supported_speeds: WrappedBitFlags<SuperSpeedDeviceCapabilitySupportedSpeed>,

	lowest_speed_supporting_full_functionality: SuperSpeedDeviceCapabilitySupportedSpeed,
	
	u1_device_latency_is_less_than_this_number_of_microseconds: u8,
	
	u2_device_latency_is_less_than_this_number_of_microseconds: u11,
}

impl SuperSpeedDeviceCapability
{
	/// Supports Latency Tolerant Messages (LTM).
	#[inline(always)]
	pub const fn supports_latency_tolerant_messages(&self) -> bool
	{
		self.supports_latency_tolerant_messages
	}
	
	#[allow(missing_docs)]
	#[inline(always)]
	pub const fn supported_speeds(&self) -> WrappedBitFlags<SuperSpeedDeviceCapabilitySupportedSpeed>
	{
		self.supported_speeds
	}
	
	/// Validated to occur within `self.supported_speeds()`.
	#[inline(always)]
	pub const fn lowest_speed_supporting_full_functionality(&self) -> SuperSpeedDeviceCapabilitySupportedSpeed
	{
		self.lowest_speed_supporting_full_functionality
	}
	
	#[allow(missing_docs)]
	#[inline(always)]
	pub const fn u1_device_latency_is_less_than_this_number_of_microseconds(&self) -> u8
	{
		self.u1_device_latency_is_less_than_this_number_of_microseconds
	}
	
	#[allow(missing_docs)]
	#[inline(always)]
	pub const fn u2_device_latency_is_less_than_this_number_of_microseconds(&self) -> u11
	{
		self.u2_device_latency_is_less_than_this_number_of_microseconds
	}
	
	#[inline(always)]
	fn parse(device_capability_bytes: &[u8]) -> Result<Self, SuperSpeedDeviceCapabilityParseError>
	{
		use SuperSpeedDeviceCapabilityParseError::*;
		
		const MinimumSize: usize = 7;
		if unlikely!(device_capability_bytes.len() < MinimumSize)
		{
			return Err(TooShort)
		}
		
		let supports_latency_tolerant_messages =
		{
			let bmAttributes = device_capability_bytes.u8_unadjusted(0);
			const Mask: u8 = 0b0010;
			if unlikely!((bmAttributes & (!Mask)) != 0)
			{
				return Err(HasReservedAttributesBitsSet)
			}
			bmAttributes & Mask != 0
		};
		
		let wSpeedsSupported = device_capability_bytes.u16_unadjusted(1);
		let supported_speeds = WrappedBitFlags::from_bits(wSpeedsSupported).map_err(|_| HasReservedSpeedsSupportedBitsSet)?;
		
		let lowest_speed_supporting_full_functionality =
		{
			use SuperSpeedDeviceCapabilitySupportedSpeed::*;
			let bFunctionalitySupport = device_capability_bytes.u8_unadjusted(3);
			let lowest_speed_supporting_full_functionality = match bFunctionalitySupport
			{
				0 => Low,
				
				1 => Full,
				
				2 => High,
				
				3 => Super,
				
				_ => return Err(HasInvalidFunctionalitySupportSpeed { bFunctionalitySupport })
			};
			if unlikely!(!supported_speeds.contains(lowest_speed_supporting_full_functionality))
			{
				return Err(HasFunctionalitySupportSpeedMissingFromSupportedSpeeds { lowest_speed_that_supports_all_functionality: lowest_speed_supporting_full_functionality })
			}
			lowest_speed_supporting_full_functionality
		};
		
		let bU1DevExitLat = device_capability_bytes.u8_unadjusted(4);
		if unlikely!(bU1DevExitLat >= 0x0B)
		{
			return Err(HasReservedU1DeviceExitLatency { bU1DevExitLat })
		}
		
		let bU2DevExitLat = device_capability_bytes.u16_unadjusted(5);
		if unlikely!(bU2DevExitLat >= 0x0800)
		{
			return Err(HasReservedU2DeviceExitLatency { bU2DevExitLat })
		}
		
		Ok
		(
			Self
			{
				supports_latency_tolerant_messages,
				
				supported_speeds,
			
				lowest_speed_supporting_full_functionality,
				
				u1_device_latency_is_less_than_this_number_of_microseconds: bU1DevExitLat,
				
				u2_device_latency_is_less_than_this_number_of_microseconds: bU2DevExitLat,
			}
		)
	}
}
