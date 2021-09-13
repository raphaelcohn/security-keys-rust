// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// Details common to a report's output or feature main item.
#[derive(Debug, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OutputOrFeatureMainItem
{
	#[serde(flatten)]
	common: OutputOrFeatureOrInputVariableCommon,
	
	array_or_variable: ArrayOrVariable,
	
	volatile: bool,
}

impl Deref for OutputOrFeatureMainItem
{
	type Target = OutputOrFeatureOrInputVariableCommon;
	
	#[inline(always)]
	fn deref(&self) -> &Self::Target
	{
		&self.common
	}
}

impl MainItem for OutputOrFeatureMainItem
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

impl OutputOrFeatureMainItem
{
	#[allow(missing_docs)]
	#[inline(always)]
	pub const fn array_or_variable(&self) -> ArrayOrVariable
	{
		self.array_or_variable
	}
	
	#[allow(missing_docs)]
	#[inline(always)]
	pub const fn volatile(&self) -> bool
	{
		self.volatile
	}
	
	#[inline(always)]
	pub(super) fn parse(data: u32, globals: Rc<GlobalItems>, locals: LocalItems) -> Self
	{
		Self
		{
			common: OutputOrFeatureOrInputVariableCommon::parse(data, globals, locals),
			
			array_or_variable: ArrayOrVariable::from(is_array(data)),
			
			volatile: parse_boolean(data, 7),
		}
	}
}
