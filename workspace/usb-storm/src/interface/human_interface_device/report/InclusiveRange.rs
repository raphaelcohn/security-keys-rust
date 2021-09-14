// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// An inclusive range.
#[derive(Debug, Clone, Eq, PartialEq, Hash)]
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
#[repr(transparent)]
pub struct InclusiveRange<V: Default + Debug + Copy + Eq + Ord + Hash>(RangeInclusive<V>);

impl<V: Default + Debug + Copy + Eq + Ord + Hash> Default for InclusiveRange<V>
{
	#[inline(always)]
	fn default() -> Self
	{
		Self(V::default() ..= V::default())
	}
}

impl<V: Default + Debug + Copy + Eq + Ord + Hash> From<RangeInclusive<V>> for InclusiveRange<V>
{
	#[inline(always)]
	fn from(value: RangeInclusive<V>) -> Self
	{
		Self(value)
	}
}

impl<V: Default + Debug + Copy + Eq + Ord + Hash> From<InclusiveRange<V>> for RangeInclusive<V>
{
	#[inline(always)]
	fn from(value: InclusiveRange<V>) -> Self
	{
		value.0
	}
}

impl<V: Default + Debug + Copy + Eq + Ord + Hash> Deref for InclusiveRange<V>
{
	type Target = RangeInclusive<V>;
	
	#[inline(always)]
	fn deref(&self) -> &Self::Target
	{
		&self.0
	}
}

impl<V: Default + Debug + Copy + Eq + Ord + Hash> PartialOrd for InclusiveRange<V>
{
	#[inline(always)]
	fn partial_cmp(&self, other: &Self) -> Option<Ordering>
	{
		Some(self.cmp(other))
	}
}

impl<V: Default + Debug + Copy + Eq + Ord + Hash> Ord for InclusiveRange<V>
{
	#[inline(always)]
	fn cmp(&self, other: &Self) -> Ordering
	{
		let left = &self.0;
		let right = &other.0;
		left.start().cmp(right.start()).then(left.end().cmp(right.end()))
	}
}

impl<V: Default + Debug + Copy + Eq + Ord + Hash + TryClone> TryClone for InclusiveRange<V>
{
	#[inline(always)]
	fn try_clone(&self) -> Result<Self, TryReserveError>
	{
		Ok(Self(self.0.clone()))
	}
}

impl<V: Default + Debug + Copy + Eq + Ord + Hash> InclusiveRange<V>
{
	/// Inclusive start.
	#[inline(always)]
	pub fn inclusive_start(&self) -> V
	{
		*self.0.start()
	}
	
	/// Inclusive end.
	#[inline(always)]
	pub fn inclusive_end(&self) -> V
	{
		*self.0.end()
	}
}

impl InclusiveRange<i32>
{
	#[allow(missing_docs)]
	#[inline(always)]
	pub fn count(&self) -> NonZeroU32
	{
		let i = self.inclusive_end() - (self.inclusive_start() + 1);
		new_non_zero_u32(i as u32)
	}
}
