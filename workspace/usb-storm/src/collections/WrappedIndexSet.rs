// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// A wrapper new type adding hashing and ordering to an `indexmap::set::IndexSet`, and support in the future for being out of memory on allocation.
#[derive(Default, Debug, Clone, PartialEq, Eq)]
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
#[repr(transparent)]
pub struct WrappedIndexSet<K: Eq + Hash + Ord>(pub IndexSet<K>);

impl<K: Eq + Hash + Ord> Deref for WrappedIndexSet<K>
{
	type Target = IndexSet<K>;
	
	#[inline(always)]
	fn deref(&self) -> &Self::Target
	{
		&self.0
	}
}

impl<K: Eq + Hash + Ord> DerefMut for WrappedIndexSet<K>
{
	#[inline(always)]
	fn deref_mut(&mut self) -> &mut Self::Target
	{
		&mut self.0
	}
}

impl<K: Eq + Hash + Ord> PartialOrd for WrappedIndexSet<K>
{
	#[inline(always)]
	fn partial_cmp(&self, other: &Self) -> Option<Ordering>
	{
		Some(self.cmp(other))
	}
}

impl<K: Eq + Hash + Ord> Ord for WrappedIndexSet<K>
{
	#[inline(always)]
	fn cmp(&self, other: &Self) -> Ordering
	{
		let left = &self.0;
		let right = &other.0;
		
		let left_length = left.len();
		let right_length = right.len();
		
		use Ordering::*;
		for index in 0 .. min(left_length, right_length)
		{
			let left_key = left.get_index(index).unwrap();
			let right_key = right.get_index(index).unwrap();
			match left_key.cmp(right_key)
			{
				Less => return Less,
				
				Greater => return Greater,
				
				Equal => continue,
			}
		}
		
		left_length.cmp(&right_length)
	}
}

impl<K: Eq + Hash + Ord> Hash for WrappedIndexSet<K>
{
	#[inline(always)]
	fn hash<H: Hasher>(&self, state: &mut H)
	{
		for key in self.iter()
		{
			key.hash(state);
		}
	}
}

impl<K: Eq + Hash + Ord> WithCapacity for WrappedIndexSet<K>
{
	#[allow(missing)]
	#[inline(always)]
	fn with_capacity<AUI: AsUsizeIndex>(capacity: AUI) -> Result<Self, TryReserveError>
	{
		Ok(Self(IndexSet::with_capacity(capacity.as_usize())))
	}
}
