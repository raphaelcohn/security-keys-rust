// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


trait Bytes
{
	#[inline(always)]
	fn version<const index: usize>(&self) -> UsbVersion
	{
		UsbVersion::from(self.u16::<index>())
	}
	
	#[inline(always)]
	fn optional_non_zero_u8<const index: usize>(&self) -> Option<NonZeroU8>
	{
		unsafe { transmute(self.u8::<index>()) }
	}
	
	fn u8<const index: usize>(&self) -> u8;
	
	fn u16<const index: usize>(&self) -> u16;
	
	fn u32<const index: usize>(&self) -> u32;
}

impl<'a> Bytes for &'a [u8]
{
	#[inline(always)]
	fn u8<const index: usize>(&self) -> u8
	{
		let adjusted_index = adjust_index::<index>();
		self.get_unchecked_value_safe(adjusted_index)
	}
	
	#[inline(always)]
	#[cfg(target_endian = "little")]
	fn u16<const index: usize>(&self) -> u16
	{
		let adjusted_index = adjust_index::<index>();
		let pointer = self.as_ptr();
		let offset = (unsafe { pointer.add(adjusted_index) }) as *const u16;
		unsafe { offset.read_unaligned() }
	}
	
	#[inline(always)]
	#[cfg(target_endian = "big")]
	fn u16<const index: usize>(&self) -> u16
	{
		let adjusted_index = adjust_index::<index>();
		u16::from_le_bytes([self.get_unchecked_value_safe(adjusted_index), self.get_unchecked_value_safe(adjusted_index + 1)])
	}
	
	#[inline(always)]
	#[cfg(target_endian = "little")]
	fn u32<const index: usize>(&self) -> u32
	{
		let adjusted_index = adjust_index::<index>();
		let pointer = self.as_ptr();
		let offset = (unsafe { pointer.add(adjusted_index) }) as *const u32;
		unsafe { offset.read_unaligned() }
	}
	
	#[inline(always)]
	#[cfg(target_endian = "big")]
	fn u32<const index: usize>(&self) -> u32
	{
		let adjusted_index = adjust_index::<index>();
		u32::from_le_bytes([self.get_unchecked_value_safe(adjusted_index), self.get_unchecked_value_safe(adjusted_index + 1), self.get_unchecked_value_safe(adjusted_index + 2), self.get_unchecked_value_safe(adjusted_index + 3)])
	}
}
