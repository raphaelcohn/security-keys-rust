// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// Collection eport items, combined from globals and locals.
#[derive(Default, Debug, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CollectionReportItems
{
	usages: Vec<Usage>,
	
	alternate_usages: Vec<Vec<Usage>>,
	
	designators: Vec<InclusiveRange<DesignatorIndex>>,
	
	strings: Vec<Option<LocalizedStrings>>,
	
	global_reserved0: Option<ReservedGlobalItem>,
	
	global_reserved1: Option<ReservedGlobalItem>,
	
	global_reserved2: Option<ReservedGlobalItem>,
	
	local_reserveds: Vec<ReservedLocalItem>,
	
	longs: Vec<LongItem>,
}

impl CollectionReportItems
{
	#[allow(missing_docs)]
	#[inline(always)]
	pub fn usages(&self) -> &[Usage]
	{
		&self.usages
	}
	
	#[allow(missing_docs)]
	#[inline(always)]
	pub fn alternate_usages(&self) -> &[Vec<Usage>]
	{
		&self.alternate_usages
	}
	
	#[allow(missing_docs)]
	#[inline(always)]
	pub fn designators(&self) -> &[InclusiveRange<DesignatorIndex>]
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
	pub const fn global_reserved0(&self) -> Option<ReservedGlobalItem>
	{
		self.global_reserved0
	}
	
	#[allow(missing_docs)]
	#[inline(always)]
	pub const fn global_reserved1(&self) -> Option<ReservedGlobalItem>
	{
		self.global_reserved1
	}
	
	#[allow(missing_docs)]
	#[inline(always)]
	pub const fn global_reserved2(&self) -> Option<ReservedGlobalItem>
	{
		self.global_reserved2
	}
	
	#[allow(missing_docs)]
	#[inline(always)]
	pub fn local_reserveds(&self) -> &[ReservedLocalItem]
	{
		&self.local_reserveds
	}
	
	#[allow(missing_docs)]
	#[inline(always)]
	pub fn longs(&self) -> &[LongItem]
	{
		&self.longs
	}
}
