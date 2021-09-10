// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// Extension controls.
#[derive(Default, Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
pub struct ExtensionControls(u64, u8);

impl<'de> Deserialize<'de> for ExtensionControls
{
	#[inline(always)]
	fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error>
	{
		struct OurVisitor;
		
		impl<'de> Visitor<'de> for OurVisitor
		{
			type Value = ExtensionControls;
			
			#[inline(always)]
			fn expecting(&self, formatter: &mut Formatter) -> fmt::Result
			{
				write!(formatter, "Extension controls")
			}
			
			#[inline(always)]
			fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error>
			{
				#[inline(always)]
				fn invalid_lenth<'de, A: SeqAccess<'de>>(size: usize)-> Result<ExtensionControls, A::Error>
				{
					Err(A::Error::invalid_length(size, &"Less than 64 controls"))
				}
				
				if let Some(size) = seq.size_hint()
				{
					if unlikely!(size > 64)
					{
						return invalid_lenth::<A>(size)
					}
				}
				
				let mut controls = 0u64;
				let mut index = 0u8;
				loop
				{
					if unlikely!(index == 64)
					{
						return invalid_lenth::<A>(64)
					}
					let control: bool = match seq.next_element()?
					{
						None => break,
						
						Some(control) => control,
					};
					controls |= (control as u64) << (index as u64);
					
					index += 1;
				}
				Ok(ExtensionControls(controls, index))
			}
		}
		
		deserializer.deserialize_seq(OurVisitor)
	}
}

impl Serialize for ExtensionControls
{
	#[inline(always)]
	fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error>
	{
		let mut sequence_serializer = serializer.serialize_seq(Some(self.1 as usize))?;
		for control in self
		{
			sequence_serializer.serialize_element(&control)?
		}
		sequence_serializer.end()
	}
}

impl IntoIterator for ExtensionControls
{
	type Item = bool;
	
	type IntoIter = ExtensionControlsIterator;
	
	#[inline(always)]
	fn into_iter(self) -> Self::IntoIter
	{
		ExtensionControlsIterator
		{
			controls: self,
			
			index: 0,
		}
	}
}

impl<'a> IntoIterator for &'a ExtensionControls
{
	type Item = bool;
	
	type IntoIter = ExtensionControlsIterator;
	
	#[inline(always)]
	fn into_iter(self) -> Self::IntoIter
	{
		ExtensionControlsIterator
		{
			controls: *self,
			
			index: 0,
		}
	}
}

impl ExtensionControls
{
	#[allow(missing_docs)]
	#[inline(always)]
	pub const fn number_of_controls(&self) -> u8
	{
		self.1
	}
	
	#[allow(missing_docs)]
	#[inline(always)]
	pub const fn control(&self, control_index: u6) -> bool
	{
		(self.0 & (1 << (control_index as u64))) != 0
	}
}
