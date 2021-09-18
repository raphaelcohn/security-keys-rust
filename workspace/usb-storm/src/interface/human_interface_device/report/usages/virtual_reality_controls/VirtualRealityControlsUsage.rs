// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// Virtual reality controls.
#[derive(Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub enum VirtualRealityControlsUsage
{
	#[allow(missing_docs)]
	Undefined,
	
	#[allow(missing_docs)]
	Devices(DevicesUsage),
	
	#[allow(missing_docs)]
	Controls(ControlsUsage),
	
	#[allow(missing_docs)]
	Reserved(u16),
}

impl Default for VirtualRealityControlsUsage
{
	#[inline(always)]
	fn default() -> Self
	{
		VirtualRealityControlsUsage::Undefined
	}
}

impl From<UsageIdentifier> for VirtualRealityControlsUsage
{
	#[inline(always)]
	fn from(identifier: UsageIdentifier) -> Self
	{
		use VirtualRealityControlsUsage::*;
		use DevicesUsage::*;
		use ControlsUsage::*;
		
		match identifier
		{
			0x00 => Undefined,
			
			0x01 => Devices(Belt),
			
			0x02 => Devices(BodySuit),
			
			0x03 => Devices(Flexor),
			
			0x04 => Devices(Glove),
			
			0x05 => Devices(HeadTracker),
			
			0x06 => Devices(HeadMountedDisplay),
			
			0x07 => Devices(HandTracker),
			
			0x08 => Devices(Oculometer),
			
			0x09 => Devices(Vest),
			
			0x0A => Devices(AnimatronicDevice),
			
			value @ 0x0B ..= 0x1F => Reserved(value),
			
			0x20 => Controls(StereoEnable),
			
			0x21 => Controls(DisplayEnable),
			
			value @ 0x22 ..= 0xFFFF => Reserved(value),
		}
	}
}
