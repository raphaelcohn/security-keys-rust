// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// Camera control.
#[derive(Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub enum CameraControlUsage
{
	#[allow(missing_docs)]
	Undefined,
	
	#[allow(missing_docs)]
	CameraAutomaticFocus,
	
	#[allow(missing_docs)]
	CameraShutter,
	
	#[allow(missing_docs)]
	Reserved(u16),
}

impl Default for CameraControlUsage
{
	#[inline(always)]
	fn default() -> Self
	{
		CameraControlUsage::Undefined
	}
}

impl From<UsageIdentifier> for CameraControlUsage
{
	#[inline(always)]
	fn from(identifier: UsageIdentifier) -> Self
	{
		use CameraControlUsage::*;
		
		match identifier
		{
			0x00 => Undefined,
			
			value @ 0x01 ..= 0x1F => Reserved(value),
			
			0x20 => CameraAutomaticFocus,
			
			0x21 => CameraShutter,
			
			value @ 0x22 ..= 0xFFFF => Reserved(value),
		}
	}
}
