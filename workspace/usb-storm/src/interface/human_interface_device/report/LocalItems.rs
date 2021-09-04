// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// Local items.
#[derive(Default, Debug, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LocalItems
{
	usages: Vec<Usage>,
	
	designators: Vec<DesignatorIndex>,
	
	strings: Vec<Option<LocalizedStrings>>,
	
	reserveds: Vec<ReservedLocalItem>,
	
	longs: Vec<LongItem>,

	sets: Vec<Self>,
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
				
				reserveds: self.reserveds.try_clone()?,
				
				longs: self.longs.try_clone()?,
				
				sets: self.sets.try_clone()?,
			}
		)
	}
}

impl LocalItems
{
	#[allow(missing_docs)]
	#[inline(always)]
	pub fn usages(&self) -> &[Usage]
	{
		&self.usages
	}
	
	#[allow(missing_docs)]
	#[inline(always)]
	pub fn designators(&self) -> &[DesignatorIndex]
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
