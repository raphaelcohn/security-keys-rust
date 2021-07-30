// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


trait Bytes
{
	#[inline(always)]
	fn version<const index: usize>(&self) -> Version
	{
		Version::from(self.u16::<index>())
	}
	
	#[inline(always)]
	fn optional_non_zero_u8<const index: usize>(&self) -> Option<NonZeroU8>
	{
		unsafe { transmute(self.u8::<index>()) }
	}
	
	fn u8<const index: usize>(&self) -> u8;
	
	fn u16<const index: usize>(&self) -> u16;
	
	fn u32<const index: usize>(&self) -> u32;
	
	fn u8_unadjusted(&self, index: usize) -> u8;
	
	fn u16_unadjusted(&self, index: usize) -> u16;
	
	fn u32_unadjusted(&self, index: usize) -> u32;
}

impl<'a> Bytes for &'a [u8]
{
	#[inline(always)]
	fn u8<const index: usize>(&self) -> u8
	{
		let adjusted_index = adjust_index::<index>();
		self.u8_unadjusted(adjusted_index)
	}
	
	#[inline(always)]
	fn u16<const index: usize>(&self) -> u16
	{
		let adjusted_index = adjust_index::<index>();
		self.u16_unadjusted(adjusted_index)
	}
	
	#[inline(always)]
	fn u32<const index: usize>(&self) -> u32
	{
		let adjusted_index = adjust_index::<index>();
		self.u32_unadjusted(adjusted_index)
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
