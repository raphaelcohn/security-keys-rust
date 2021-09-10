// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// Billboard alternate mode configuration.
#[derive(Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
#[repr(u8)]
pub enum BillboardAlternateModeConfigurationResult
{
	#[allow(missing_docs)]
	UnspecifiedError = 0b00,
	
	#[allow(missing_docs)]
	ConfigurationNotAttemptedOrExited = 0b01,
	
	#[allow(missing_docs)]
	ConfigurationAttemptedButUnsuccesfulAndNotEntered = 0b10,
	
	#[allow(missing_docs)]
	ConfigurationSuccessful = 0b11,
}

impl BillboardAlternateModeConfigurationResult
{
	#[inline(always)]
	fn parse(index: usize, configured: &[u8]) -> Self
	{
		const BitsPerByte: usize = 8;
		
		let absolute_bit_index = index * 2;
		let byte_index = absolute_bit_index / BitsPerByte;
		let relative_bit_index = (absolute_bit_index % BitsPerByte) as u8;
		
		let value = (configured.get_unchecked_value_safe(byte_index) >> relative_bit_index) & 0b11;
		unsafe { transmute(value) }
	}
}
