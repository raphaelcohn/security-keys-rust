// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// Details common to a report's output, feature or input variable main item.
#[derive(Debug, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OutputOrFeatureOrInputVariableCommon
{
	#[serde(flatten)]
	common: MainItemCommon,
	
	wraps: bool,
	
	linear_or_non_linear: LinearOrNonLinear,

	has_preferred_state: bool,

	has_null_state: bool,

	bit_field_or_buffered_bytes: BitFieldOrBufferedBytes,
}

impl Deref for OutputOrFeatureOrInputVariableCommon
{
	type Target = MainItemCommon;
	
	#[inline(always)]
	fn deref(&self) -> &Self::Target
	{
		&self.common
	}
}

impl MainItem for OutputOrFeatureOrInputVariableCommon
{
	#[inline(always)]
	fn globals(&self) -> &GlobalItems
	{
		self.common.globals()
	}
	
	#[inline(always)]
	fn locals(&self) -> &LocalItems
	{
		self.common.locals()
	}
}

impl OutputOrFeatureOrInputVariableCommon
{
	#[allow(missing_docs)]
	#[inline(always)]
	pub const fn wraps(&self) -> bool
	{
		self.wraps
	}
	
	#[allow(missing_docs)]
	#[inline(always)]
	pub const fn linear_or_non_linear(&self) -> LinearOrNonLinear
	{
		self.linear_or_non_linear
	}
	
	#[allow(missing_docs)]
	#[inline(always)]
	pub const fn has_preferred_state(&self) -> bool
	{
		self.has_preferred_state
	}
	
	#[allow(missing_docs)]
	#[inline(always)]
	pub const fn has_null_state(&self) -> bool
	{
		self.has_null_state
	}
	
	#[allow(missing_docs)]
	#[inline(always)]
	pub const fn bit_field_or_buffered_bytes(&self) -> BitFieldOrBufferedBytes
	{
		self.bit_field_or_buffered_bytes
	}
	
	#[inline(always)]
	pub(super) fn parse(data: u32, globals: Rc<GlobalItems>, locals: LocalItems) -> Self
	{
		Self
		{
			common: MainItemCommon::parse(data, globals, locals),
			
			wraps: parse_boolean(data, 3),
			
			linear_or_non_linear: parse_boolean_enum(data, 4),
			
			has_preferred_state: !parse_boolean(data, 5),
			
			has_null_state: parse_boolean(data, 6),
			
			bit_field_or_buffered_bytes: parse_boolean_enum(data, 8),
		}
	}
}
