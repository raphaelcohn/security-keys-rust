// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// An iterator over extension controls.
#[derive(Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
pub struct ExtensionControlsIterator
{
	controls: ExtensionControls,
	
	index: u8,
}

impl Iterator for ExtensionControlsIterator
{
	type Item = bool;
	
	#[inline(always)]
	fn next(&mut self) -> Option<Self::Item>
	{
		if unlikely!(self.controls.number_of_controls() == self.index)
		{
			None
		}
		else
		{
			let control = self.controls.control(self.index);
			self.index += 1;
			Some(control)
		}
	}
	
	#[inline(always)]
	fn size_hint(&self) -> (usize, Option<usize>)
	{
		let remaining_length = self.remaining_length();
		(remaining_length, Some(remaining_length))
	}
}

impl ExactSizeIterator for ExtensionControlsIterator
{
	#[inline(always)]
	fn len(&self) -> usize
	{
		self.remaining_length()
	}
}

impl FusedIterator for ExtensionControlsIterator
{
}

impl ExtensionControlsIterator
{
	#[inline(always)]
	const fn remaining_length(&self) -> usize
	{
		(self.controls.number_of_controls() - self.index) as usize
	}
}
