// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// A card reader name should be 128 bytes, including the trailing ASCII NULL.
///
/// There are latent bugs in PCSC that permit a reader name of 128 bytes *excluding* the trailing ASCII NULL.
#[derive(Debug, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
pub struct CardReaderName<'a>(Cow<'a, CStr>);

impl<'a> TryFrom<&'a CStr> for CardReaderName<'a>
{
	type Error = CardReaderNameError;
	
	#[inline(always)]
	fn try_from(c_str: &'a CStr) -> Result<Self, Self::Error>
	{
		Self::validate(c_str)?;
		Ok(Self::borrow(c_str))
	}
}

impl TryFrom<CString> for CardReaderName<'static>
{
	type Error = CardReaderNameError;
	
	#[inline(always)]
	fn try_from(c_string: CString) -> Result<Self, Self::Error>
	{
		Self::validate(c_string.as_c_str())?;
		Ok(Self(Cow::Owned(c_string)))
	}
}

impl<'a> Deref for CardReaderName<'a>
{
	type Target = CStr;
	
	#[inline(always)]
	fn deref(&self) -> &Self::Target
	{
		self.0.borrow()
	}
}

impl<'a> CardReaderName<'a>
{
	/// Into owned.
	#[inline(always)]
	pub fn into_owned(self) -> CardReaderName<'static>
	{
		CardReaderName(Cow::Owned(self.0.into_owned()))
	}
	
	/// Into a `CString`.
	#[inline(always)]
	pub fn into_c_string(self) -> CString
	{
		self.0.into_owned()
	}
	
	#[inline(always)]
	fn validate(c_str: &CStr) -> Result<(), CardReaderNameError>
	{
		use self::CardReaderNameError::*;
		
		let bytes = c_str.to_bytes_with_nul();
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
			Ok(())
		}
	}
	
	#[inline(always)]
	fn as_ptr(&self) -> *const c_char
	{
		self.0.as_ptr()
	}
	
	#[inline(always)]
	pub(in crate::pcsc) fn wrap_buffer(buffer: &'a [u8], null_index: usize) -> Self
	{
		let bytes = buffer.get_unchecked_range_safe(0 .. null_index);
		let length = bytes.len();
		
		debug_assert!(length <= MAX_READERNAME, "ReaderName too long ({})", length);
		debug_assert_ne!(length, 0);
		debug_assert_ne!(length, 1);
		debug_assert_eq!(bytes.get_unchecked_value_safe(length - 1), 0x00);
		
		Self::borrow(unsafe { CStr::from_bytes_with_nul_unchecked(bytes) })
	}
	
	#[inline(always)]
	fn new_unchecked(bytes: *const c_char) -> Self
	{
		Self::borrow(unsafe { CStr::from_ptr(bytes) })
	}
	
	#[inline(always)]
	fn borrow(c_str: &'a CStr) -> Self
	{
		Self(Cow::Borrowed(c_str))
	}
}

impl CardReaderName<'static>
{
	/// See <https://doc.rust-lang.org/std/ffi/struct.CString.html#method.new> for similar usages.
	#[inline(always)]
	pub fn new<T: Into<Vec<u8>>>(t: T) -> Result<Self, CardReaderNameError>
	{
		let c_string = CString::new(t).map_err(CardReaderNameError::Nul)?;
		Self::try_from(c_string)
	}
}
