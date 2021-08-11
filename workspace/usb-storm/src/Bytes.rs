// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


trait Bytes
{
	fn bytes_unadjusted(&self, index: usize, length: usize) -> &[u8];
	
	#[inline(always)]
	fn version_adjusted<const index: usize>(&self) -> Result<Version, VersionParseError>
	{
		self.version_unadjusted(adjust_index::<index>())
	}
	
	#[inline(always)]
	fn version_unadjusted(&self, index: usize) -> Result<Version, VersionParseError>
	{
		Version::parse(self.u16_unadjusted(index))
	}
	
	fn uuid_unadjusted(&self, index: usize) -> Uuid;
	
	#[inline(always)]
	fn optional_non_zero_u8_adjusted<const index: usize>(&self) -> Option<NonZeroU8>
	{
		let adjusted_index = adjust_index::<index>();
		self.optional_non_zero_u8_unadjusted(adjusted_index)
	}
	
	#[inline(always)]
	fn optional_non_zero_u8_unadjusted(&self, index: usize) -> Option<NonZeroU8>
	{
		unsafe { transmute(self.u8_unadjusted(index)) }
	}
	
	#[inline(always)]
	fn optional_non_zero_u16_unadjusted(&self, index: usize) -> Option<NonZeroU16>
	{
		unsafe { transmute(self.u16_unadjusted(index)) }
	}
	
	#[inline(always)]
	fn u8_adjusted<const index: usize>(&self) -> u8
	{
		let adjusted_index = adjust_index::<index>();
		self.u8_unadjusted(adjusted_index)
	}
	
	fn u8_unadjusted(&self, index: usize) -> u8;
	
	#[inline(always)]
	fn u16_adjusted<const index: usize>(&self) -> u16
	{
		let adjusted_index = adjust_index::<index>();
		self.u16_unadjusted(adjusted_index)
	}
	
	fn u16_unadjusted(&self, index: usize) -> u16;
	
	#[inline(always)]
	fn u32_adjusted<const index: usize>(&self) -> u32
	{
		let adjusted_index = adjust_index::<index>();
		self.u32_unadjusted(adjusted_index)
	}
	
	fn u32_unadjusted(&self, index: usize) -> u32;
}

impl<'a> Bytes for &'a [u8]
{
	#[inline(always)]
	fn bytes_unadjusted(&self, index: usize, length: usize) -> &[u8]
	{
		self.get_unchecked_range_safe(index .. (index + length))
	}
	
	#[inline(always)]
	fn uuid_unadjusted(&self, index: usize) -> Uuid
	{
		let pointer = self.as_ptr();
		let uuid_bytes = unsafe { (pointer.add(index) as *const [u8; 16]).read_volatile() };
		
		// It seems UUIDs are stored big-endian, although the USB 3.2 specification isn't clear on this and everything else in USB is stored little endian.
		Uuid::from_bytes(uuid_bytes)
	}
	
	#[inline(always)]
	fn u8_unadjusted(&self, index: usize) -> u8
	{
		self.get_unchecked_value_safe(index)
	}
	
	#[inline(always)]
	#[cfg(target_endian = "little")]
	fn u16_unadjusted(&self, index: usize) -> u16
	{
		let pointer = self.as_ptr();
		let offset = (unsafe { pointer.add(index) }) as *const u16;
		unsafe { offset.read_unaligned() }
	}
	
	#[inline(always)]
	#[cfg(target_endian = "big")]
	fn u16_unadjusted(&self, index: usize) -> u16
	{
		u16::from_le_bytes([self.get_unchecked_value_safe(index), self.get_unchecked_value_safe(adjusted_index + 1)])
	}
	
	#[inline(always)]
	#[cfg(target_endian = "little")]
	fn u32_unadjusted(&self, index: usize) -> u32
	{
		let pointer = self.as_ptr();
		let offset = (unsafe { pointer.add(index) }) as *const u32;
		unsafe { offset.read_unaligned() }
	}
	
	#[inline(always)]
	#[cfg(target_endian = "big")]
	fn u32_unadjusted(&self, index: usize) -> u32
	{
		u32::from_le_bytes([self.get_unchecked_value_safe(index), self.get_unchecked_value_safe(index + 1), self.get_unchecked_value_safe(index + 2), self.get_unchecked_value_safe(index + 3)])
	}
}
