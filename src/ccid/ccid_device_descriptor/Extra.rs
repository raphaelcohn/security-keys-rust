// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


trait Extra
{
	#[inline(always)]
	fn kilohertz(&self, index: usize) -> Kilohertz
	{
		self.u32(index)
	}
	
	#[inline(always)]
	fn baud(&self, index: usize) -> Baud
	{
		self.u32(index)
	}
	
	#[inline(always)]
	fn optional_non_zero_u8(&self, index: usize) -> Option<NonZeroU8>
	{
		unsafe { transmute(self.u8(index)) }
	}
	
	fn u8(&self, index: usize) -> u8;
	
	fn u16(&self, index: usize) -> u16;
	
	fn u32(&self, index: usize) -> u32;
}

impl<'a> Extra for &'a [u8; CcidDeviceDescriptor::<'static>::Length]
{
	#[inline(always)]
	fn u8(&self, index: usize) -> u8
	{
		self.get_unchecked_value_safe(index)
	}
	
	#[inline(always)]
	#[cfg(target_endian = "little")]
	fn u16(&self, index: usize) -> u16
	{
		let pointer = self.as_ptr();
		let offset = (unsafe { pointer.add(index) }) as *const u16;
		unsafe { offset.read_unaligned() }
	}
	
	#[inline(always)]
	#[cfg(target_endian = "big")]
	fn u16(&self, index: usize) -> u16
	{
		u16::from_le_bytes([self.get_unchecked_value_safe(index), self.get_unchecked_value_safe(index + 1)])
	}
	
	#[inline(always)]
	#[cfg(target_endian = "little")]
	fn u32(&self, index: usize) -> u32
	{
		let pointer = self.as_ptr();
		let offset = (unsafe { pointer.add(index) }) as *const u32;
		unsafe { offset.read_unaligned() }
	}
	
	#[inline(always)]
	#[cfg(target_endian = "big")]
	fn u32(&self, index: usize) -> u32
	{
		u32::from_le_bytes([self.get_unchecked_value_safe(index), self.get_unchecked_value_safe(index + 1), self.get_unchecked_value_safe(index + 2), self.get_unchecked_value_safe(index + 3)])
	}
}
