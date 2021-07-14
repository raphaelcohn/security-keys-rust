// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// A card reader name should be 128 bytes, including the trailing ASCII NULL.
///
/// There are latent bugs in PCSC that permit a reader name of 128 bytes *excluding* the trailing ASCII NULL.
#[derive(Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
pub(crate) struct CardReaderName<'a>(&'a CStr);

impl<'a> TryFrom<&'a CStr> for CardReaderName<'a>
{
	type Error = CardReaderNameError;
	
	#[inline(always)]
	fn try_from(c_string: &'a CStr) -> Result<Self, Self::Error>
	{
		use self::CardReaderNameError::*;
		
		let bytes = c_string.to_bytes_with_nul();
		let length = bytes.len();
		if unlikely!(length == 0)
		{
			Err(Empty)
		}
		else if unlikely!(length > MAX_READERNAME)
		{
			Err(TooLong(length))
		}
		else
		{
			Ok(Self(c_string))
		}
	}
}

impl<'a> CardReaderName<'a>
{
	#[inline(always)]
	fn as_ptr(&self) -> *const c_char
	{
		self.0.as_ptr()
	}
	
	#[inline(always)]
	fn wrap_buffer(buffer: &'a [u8], null_index: usize) -> Self
	{
		let bytes = buffer.get_unchecked_range_safe(0 .. null_index);
		let length = bytes.len();
		
		debug_assert!(length <= MAX_READERNAME, "ReaderName too long ({})", length);
		debug_assert_ne!(length, 0);
		debug_assert_ne!(length, 1);
		debug_assert_eq!(bytes.get_unchecked_value_safe(length - 1), 0x00);
		
		Self(unsafe { CStr::from_bytes_with_nul_unchecked(bytes) })
	}
	
	#[inline(always)]
	fn new_unchecked(bytes: *const c_char) -> Self
	{
		Self(unsafe { CStr::from_ptr(bytes) })
	}
}
