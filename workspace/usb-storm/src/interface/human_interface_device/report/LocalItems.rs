// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// Local items.
#[derive(Default, Debug, Clone, Eq, PartialEq, Hash)]
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LocalItems
{
	usages: Vec<RangeInclusive<Usage>>,
	
	designators: Vec<RangeInclusive<DesignatorIndex>>,
	
	strings: Vec<Option<LocalizedStrings>>,
	
	sets: Vec<Self>,
	
	reserveds: Vec<ReservedLocalItem>,
	
	longs: Vec<LongItem>,
}

impl TryClone for LocalItems
{
	#[inline(always)]
	fn try_clone(&self) -> Result<Self, TryReserveError>
	{
		Ok
		(
			Self
			{
				usages: self.usages.try_clone()?,
				
				designators: self.designators.try_clone()?,
				
				strings: self.strings.try_clone()?,
				
				sets: self.sets.try_clone()?,
				
				reserveds: self.reserveds.try_clone()?,
				
				longs: self.longs.try_clone()?,
			}
		)
	}
}

impl PartialOrd for LocalItems
{
	#[inline(always)]
	fn partial_cmp(&self, other: &Self) -> Option<Ordering>
	{
		Some(self.cmp(other))
	}
}

impl Ord for LocalItems
{
	#[inline(always)]
	fn cmp(&self, other: &Self) -> Ordering
	{
		Self::compare_slice_range_inclusive(&self.usages, &other.usages).then_with(|| Self::compare_slice_range_inclusive(&self.designators, &other.designators)).then_with(|| self.strings.cmp(&other.strings)).then_with(|| self.sets.cmp(&other.sets)).then_with(|| self.reserveds.cmp(&other.reserveds)).then_with(|| self.longs.cmp(&other.longs))
	}
}

impl LocalItems
{
	#[inline(always)]
	fn compare_slice_range_inclusive<V: Ord>(left: &[RangeInclusive<V>], right: &[RangeInclusive<V>]) -> Ordering
	{
		use Ordering::*;
		
		let left_length = left.len();
		let right_length = right.len();
		let shortest_length = min(left_length, right_length);
		
		// Slice to the loop iteration range to enable bound check elimination in the compiler
		let left = left.get_unchecked_range_safe(.. shortest_length);
		let right = right.get_unchecked_range_safe( .. shortest_length);
		
		for index in 0 .. shortest_length
		{
			let left = left.get_unchecked_safe(index);
			let right = right.get_unchecked_safe(index);
			match Self::compare_range_inclusive(left, right)
			{
				Less => return Less,
				
				Equal => (),
				
				Greater => return Greater,
			}
		}
		
		left_length.cmp(&right_length)
	}
	
	#[inline(always)]
	fn compare_range_inclusive<V: Ord>(left: &RangeInclusive<V>, right: &RangeInclusive<V>) -> Ordering
	{
		left.start().cmp(right.start()).then(left.end().cmp(right.end()))
	}
	
	#[allow(missing_docs)]
	#[inline(always)]
	pub fn usages(&self) -> &[RangeInclusive<Usage>]
	{
		&self.usages
	}
	
	#[allow(missing_docs)]
	#[inline(always)]
	pub fn designators(&self) -> &[RangeInclusive<DesignatorIndex>]
	{
		&self.designators
	}
	
	#[allow(missing_docs)]
	#[inline(always)]
	pub fn strings(&self) -> &[Option<LocalizedStrings>]
	{
		&self.strings
	}
	
	#[allow(missing_docs)]
	#[inline(always)]
	pub fn sets(&self) -> &[Self]
	{
		&self.sets
	}
	
	#[allow(missing_docs)]
	#[inline(always)]
	pub fn reserveds(&self) -> &[ReservedLocalItem]
	{
		&self.reserveds
	}
	
	#[allow(missing_docs)]
	#[inline(always)]
	pub fn longs(&self) -> &[LongItem]
	{
		&self.longs
	}
}
