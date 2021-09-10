// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// Parse error.
#[derive(Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub enum CameraParseError
{
	#[allow(missing_docs)]
	BLengthTooShort,
	
	#[allow(missing_docs)]
	MixOfOpticalZoomAndNonZoomSettings,
	
	#[allow(missing_docs)]
	MaximumObjectiveIsLessThanMinimumObjective
	{
		minimum_objective: FocalLength,
		
		maximum_objective: FocalLength,
		
		ocular: FocalLength,
	},
	
	#[allow(missing_docs)]
	Version_1_5_HasInvalidControlSize
	{
		bControlSize: u8,
	},
	
	#[allow(missing_docs)]
	BLengthTooShortForControlSize
	{
		bControlSize: u8,
	},
}

impl Display for CameraParseError
{
	#[inline(always)]
	fn fmt(&self, f: &mut Formatter) -> fmt::Result
	{
		Debug::fmt(self, f)
	}
}

impl error::Error for CameraParseError
{
}
