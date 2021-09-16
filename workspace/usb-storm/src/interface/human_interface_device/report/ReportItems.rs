// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// Report items.
///
/// * The range of values in `self.logical_extent()` is the range of values possible in a report field.
/// * The size, in bits, of a report field is given by `self.report_size()`.
/// 	* This is validated to support the range of values above.
/// * The number of report fields is given by `self.report_count()`.
/// * The total number of bits of all report fields is given by `self.report_bit_length()`.
/// 	* This is validated to not exceed a sensible maximum.
/// * The `self.usages()` should contain an entry for each report field, but this is not necessarily the case
/// 	* If `self.usages().len() < self.report_count()`: The last entry in `self.usages()` is repeated for the remaining fields.
/// 	* If `self.usages().len() == self.report_count()`: Assign 1:1.
/// 	* If `self.usages().len() > self.report_count()`: Ignore final usages.
/// * Likewise, `self.alternate_usages()` can also be used.
#[derive(Debug, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReportItems
{
	usages: Vec<Usage>,
	
	alternate_usages: Vec<Vec<Usage>>,
	
	report_identifier: Option<ReportIdentifier>,
	
	report_size: ReportSize,
	
	report_count: ReportCount,
	
	report_bit_length: NonZeroU32,
	
	logical_extent: InclusiveRange<i32>,
	
	physical_extent: InclusiveRange<i32>,

	physical_unit: PhysicalUnit,
	
	designators: Vec<InclusiveRange<DesignatorIndex>>,
	
	strings: Vec<Option<LocalizedStrings>>,
	
	global_reserved0: Option<ReservedGlobalItem>,
	
	global_reserved1: Option<ReservedGlobalItem>,
	
	global_reserved2: Option<ReservedGlobalItem>,
	
	local_reserveds: Vec<ReservedLocalItem>,
	
	longs: Vec<LongItem>,
}

impl ReportItems
{
	/// Will not exceed `(i32::MAX as u32) + 1`.
	///
	/// Only relevant if the item is an array.
	#[inline(always)]
	pub fn number_of_array_items(&self) -> NonZeroU32
	{
		self.logical_extent.count()
	}
	
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
	pub const fn report_identifier(&self) -> Option<ReportIdentifier>
	{
		self.report_identifier
	}
	
	#[allow(missing_docs)]
	#[inline(always)]
	pub const fn report_size(&self) -> ReportSize
	{
		self.report_size
	}
	
	#[allow(missing_docs)]
	#[inline(always)]
	pub const fn report_count(&self) -> ReportCount
	{
		self.report_count
	}
	
	// This constant is taken from Linux.
	const HID_MAX_BUFFER_SIZE: u32 = 16384;
	
	/// Limitation from Linux of 131,064.
	pub const ReportBitLengthInclusiveMaximum: NonZeroU32 = new_non_zero_u32((Self::HID_MAX_BUFFER_SIZE - 1) << 3);
	
	/// This value is a number of bits; it does not exceed `Self::ReportBitLengthInclusiveMaximum`.
	#[inline(always)]
	pub const fn report_bit_length(&self) -> NonZeroU32
	{
		self.report_bit_length
	}
	
	#[allow(missing_docs)]
	#[inline(always)]
	pub const fn logical_extent(&self) -> &InclusiveRange<i32>
	{
		&self.logical_extent
	}
	
	#[allow(missing_docs)]
	#[inline(always)]
	pub const fn physical_extent(&self) -> &InclusiveRange<i32>
	{
		&self.physical_extent
	}
	
	#[allow(missing_docs)]
	#[inline(always)]
	pub const fn physical_unit(&self) -> PhysicalUnit
	{
		self.physical_unit
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
