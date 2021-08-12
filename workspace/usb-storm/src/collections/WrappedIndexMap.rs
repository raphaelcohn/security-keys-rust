// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// A wrapper new type adding hashing and ordering to an `indexmap::map::IndexMap`, and support in the future for being out of memory on allocation.
#[derive(Default, Debug, Clone, PartialEq, Eq)]
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
#[repr(transparent)]
pub struct WrappedIndexMap<K: Eq + Hash + Ord, V>(pub IndexMap<K, V>);

impl<K: Eq + Hash + Ord, V: PartialEq + Ord> Deref for WrappedIndexMap<K, V>
{
	type Target = IndexMap<K, V>;
	
	#[inline(always)]
	fn deref(&self) -> &Self::Target
	{
		&self.0
	}
}

impl<K: Eq + Hash + Ord, V: PartialEq + Ord> DerefMut for WrappedIndexMap<K, V>
{
	#[inline(always)]
	fn deref_mut(&mut self) -> &mut Self::Target
	{
		&mut self.0
	}
}

impl<K: Eq + Hash + Ord, V: PartialEq + Ord> PartialOrd for WrappedIndexMap<K, V>
{
	#[inline(always)]
	fn partial_cmp(&self, other: &Self) -> Option<Ordering>
	{
		Some(self.cmp(other))
	}
}

impl<K: Eq + Hash + Ord, V: PartialEq + Ord> Ord for WrappedIndexMap<K, V>
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
			let (left_key, left_value) = left.get_index(index).unwrap();
			let (right_key, right_value) = right.get_index(index).unwrap();
			match left_key.cmp(right_key)
			{
				Less => return Less,
				
				Greater => return Greater,
				
				Equal => match left_value.cmp(right_value)
				{
					Less => return Less,
					
					Greater => return Greater,
					
					Equal => continue,
				}
			}
		}
		
		left_length.cmp(&right_length)
	}
}

impl<K: Eq + Hash + Ord, V: PartialEq + Ord + Hash> Hash for WrappedIndexMap<K, V>
{
	#[inline(always)]
	fn hash<H: Hasher>(&self, state: &mut H)
	{
		for (key, value) in self.iter()
		{
			key.hash(state);
			value.hash(state);
		}
	}
}

impl<K: Eq + Hash + Ord, V: PartialEq + Ord> WithCapacity for WrappedIndexMap<K, V>
{
	#[allow(missing)]
	#[inline(always)]
	fn with_capacity<AUI: AsUsizeIndex>(capacity: AUI) -> Result<Self, TryReserveError>
	{
		Ok(Self(IndexMap::with_capacity(capacity.as_usize())))
	}
}
