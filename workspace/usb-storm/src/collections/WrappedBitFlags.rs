// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// Wrapped.
#[derive(Default, Debug, Copy, Clone)]
#[repr(transparent)]
pub struct WrappedBitFlags<T: BitFlag>(BitFlags<T>);

impl<'a, T: BitFlag> Deserialize<'a> for WrappedBitFlags<T>
where T::Numeric: Deserialize<'a> + Into<u64>
{
	#[inline(always)]
	fn deserialize<D: Deserializer<'a>>(d: D) -> Result<Self, D::Error>
	{
		let value = T::Numeric::deserialize(d)?;
		Self::from_bits(value).map_err(|_| D::Error::invalid_value(Unexpected::Unsigned(value.into()),&"valid bit representation"))
	}
}

impl<T: BitFlag> Serialize for WrappedBitFlags<T>
where T::Numeric: Serialize
{
	#[inline(always)]
	fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error>
	{
		self.0.bits().serialize(serializer)
	}
}

impl<T: BitFlag> PartialEq for WrappedBitFlags<T>
{
	#[inline(always)]
	fn eq(&self, other: &Self) -> bool
	{
		self.0.bits() == other.0.bits()
	}
}

impl<T: BitFlag> Eq for WrappedBitFlags<T>
{
}

impl<T: BitFlag> Hash for WrappedBitFlags<T>
where T::Numeric: Hash
{
	#[inline(always)]
	fn hash<H: Hasher>(&self, state: &mut H)
	{
		self.0.bits().hash(state)
	}
}

impl<T: BitFlag> PartialOrd for WrappedBitFlags<T>
{
	#[inline(always)]
	fn partial_cmp(&self, other: &Self) -> Option<Ordering>
	{
		Some(self.cmp(other))
	}
}

impl<T: BitFlag> Ord for WrappedBitFlags<T>
{
	#[inline(always)]
	fn cmp(&self, other: &Self) -> Ordering
	{
		use Ordering::*;
		
		let left = self.0;
		let right = other.0;
		
		for bit in T::FLAG_LIST
		{
			let bit = *bit;
			match (left.contains(bit), right.contains(bit))
			{
				(true, true) => continue,
				
				(false, false) => continue,
				
				(true, false) => return Greater,
				
				(false, true) => return Less,
			}
		}
		Equal
	}
}

impl<T: BitFlag> WrappedBitFlags<T>
{
	#[allow(missing_docs)]
	#[inline(always)]
	pub fn number_of_bits_set(self) -> usize
	{
		let mut length = 0;
		for _ in self.0.iter()
		{
			length += 1
		}
		length
	}
}

impl<T: BitFlag> WrappedBitFlags<T>
{
	#[allow(missing_docs)]
	#[inline(always)]
	pub fn from_bits(bits: T::Numeric) -> Result<Self, FromBitsError<T>>
	{
		BitFlags::from_bits(bits).map(Self)
	}
	
	#[allow(missing_docs)]
	#[inline(always)]
	pub fn from_bits_unchecked(bits: T::Numeric) -> Self
	{
		Self(unsafe { BitFlags::from_bits_unchecked(bits) })
	}
	
	#[allow(missing_docs)]
	#[inline(always)]
	pub fn from_bits_truncate(bits: T::Numeric) -> Self
	{
		Self(BitFlags::from_bits_truncate(bits))
	}
	
	#[allow(missing_docs)]
	#[inline(always)]
	pub fn iter(self) -> impl Iterator<Item=T>
	{
		self.0.iter()
	}
	
	#[allow(missing_docs)]
	#[inline(always)]
	pub fn contains(self, other: T) -> bool
	{
		self.0.contains(other)
	}
	
	#[allow(missing_docs)]
	#[inline(always)]
	pub fn is_empty(self) -> bool
	{
		self.0.is_empty()
	}
}
