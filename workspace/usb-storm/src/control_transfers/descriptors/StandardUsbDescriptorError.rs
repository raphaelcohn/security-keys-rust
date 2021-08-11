// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// An error when getting a descriptor.
#[derive(Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
pub enum StandardUsbDescriptorError
{
	/// A descriptor was too short.
	TooShort
	{
		/// Zero or One.
		length: usize,
	},
	
	/// A descriptor's `bLength` field exceeds the number of bytes returned (the standard permits the opposite, however).
	ReportedLengthTooLong
	{
		#[allow(missing_docs)]
		length: usize,
		
		#[allow(missing_docs)]
		bLength: u8,
	},
	
	#[allow(missing_docs)]
	DescriptorMismatch
	{
		descriptor_type: DescriptorType,
		
		bDescriptorType: DescriptorType,
	}
}

impl Display for StandardUsbDescriptorError
{
	#[inline(always)]
	fn fmt(&self, f: &mut Formatter) -> fmt::Result
	{
		Debug::fmt(self, f)
	}
}

impl error::Error for StandardUsbDescriptorError
{
}

impl StandardUsbDescriptorError
{
	#[inline(always)]
	fn parse<const descriptor_type: DescriptorType>(descriptor_bytes: DeadOrAlive<Option<&[u8]>>) -> Result<DeadOrAlive<Option<(&[u8], u8)>>, Self>
	{
		use StandardUsbDescriptorError::*;
		
		let descriptor_bytes = return_ok_if_dead_or_alive_none!(descriptor_bytes);
		
		let length = descriptor_bytes.len() as usize;
		if unlikely!(length < MinimumStandardUsbDescriptorLength)
		{
			return Err(TooShort { length })
		}
		
		let bLength = descriptor_bytes.get_unchecked_value_safe(0);
		if unlikely!((bLength as usize) > length)
		{
			return Err(ReportedLengthTooLong { length, bLength })
		}
		
		let bDescriptorType = descriptor_bytes.get_unchecked_value_safe(1);
		if unlikely!(bDescriptorType != descriptor_type)
		{
			return Err(DescriptorMismatch { descriptor_type, bDescriptorType })
		}
		
		let remaining_bytes = descriptor_bytes.get_unchecked_range_safe(MinimumStandardUsbDescriptorLength ..);
		Ok(Alive(Some((remaining_bytes, bLength))))
	}
}
