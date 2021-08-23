// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// Associated interfaces.
#[derive(Default, Debug, Clone, Eq, PartialEq, Hash)]
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AssociatedInterfaces(Range<InterfaceNumber>);

impl PartialOrd for AssociatedInterfaces
{
	#[inline(always)]
	fn partial_cmp(&self, other: &Self) -> Option<Ordering>
	{
		Some(self.cmp(other))
	}
}

impl Ord for AssociatedInterfaces
{
	#[inline(always)]
	fn cmp(&self, other: &Self) -> Ordering
	{
		let left_start = self.0.start;
		let right_start = other.0.start;
		
		use Ordering::*;
		
		match left_start.cmp(&right_start)
		{
			Less => return Less,
			
			Equal => (),
			
			Greater => return Greater,
		};
		
		let left_end = self.0.end;
		let right_end = other.0.end;
		left_end.cmp(&right_end)
	}
}

impl Into<Range<InterfaceNumber>> for AssociatedInterfaces
{
	#[inline(always)]
	fn into(self) -> Range<InterfaceNumber>
	{
		self.0
	}
}

impl Iterator for AssociatedInterfaces
{
	type Item = InterfaceNumber;
	
	#[inline(always)]
	fn next(&mut self) -> Option<Self::Item>
	{
		self.0.next()
	}
}

impl DoubleEndedIterator for AssociatedInterfaces
{
	#[inline(always)]
	fn next_back(&mut self) -> Option<Self::Item>
	{
		self.0.next_back()
	}
}

impl ExactSizeIterator for AssociatedInterfaces
{
	#[inline(always)]
	fn len(&self) -> usize
	{
		self.0.len()
	}
}

unsafe impl TrustedLen for AssociatedInterfaces
{
}

impl FusedIterator for AssociatedInterfaces
{
}

impl RangeBounds<InterfaceNumber> for AssociatedInterfaces
{
	#[inline(always)]
	fn start_bound(&self) -> Bound<&InterfaceNumber>
	{
		self.0.start_bound()
	}
	
	#[inline(always)]
	fn end_bound(&self) -> Bound<&InterfaceNumber>
	{
		self.0.end_bound()
	}
	
	#[inline(always)]
	fn contains<U>(&self, item: &U) -> bool
	where InterfaceNumber: PartialOrd<U>, U: ?Sized + PartialOrd<InterfaceNumber>,
	{
		self.0.contains(item)
	}
}

impl AssociatedInterfaces
{
	#[inline(always)]
	fn parse(descriptor_body: &[u8]) -> Result<Self, InterfaceAssociationConfigurationExtraDescriptorParseError>
	{
		use InterfaceAssociationConfigurationExtraDescriptorParseError::*;
		
		let first_inclusive_contiguous_interface_number =
		{
			let bFirstInterface = descriptor_body.u8(descriptor_index::<2>());
			if unlikely!(bFirstInterface >= MaximumNumberOfInterfaces)
			{
				return Err(InterfaceNumberTooLarge { bFirstInterface })
			}
			bFirstInterface
		};
		
		let last_exclusive_contiguous_interface_number =
		{
			let bInterfaceCount = descriptor_body.u8(descriptor_index::<3>());
			if unlikely!(bInterfaceCount > MaximumNumberOfInterfaces)
			{
				return Err(InterfaceCountTooLarge { bInterfaceCount })
			}
			let last_exclusive_contiguous_interface_number = first_inclusive_contiguous_interface_number + bInterfaceCount;
			if unlikely!(last_exclusive_contiguous_interface_number > MaximumNumberOfInterfaces)
			{
				return Err(LastExclusiveInterfaceNumberOutOfRange { first_inclusive_contiguous_interface_number, bInterfaceCount })
			}
			last_exclusive_contiguous_interface_number
		};
		
		Ok(Self(first_inclusive_contiguous_interface_number .. last_exclusive_contiguous_interface_number))
	}
}
