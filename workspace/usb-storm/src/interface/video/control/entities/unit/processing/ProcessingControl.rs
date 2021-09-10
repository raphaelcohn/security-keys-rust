// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// A processing control.
#[derive(Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
#[bitflags]
#[repr(u32)]
pub enum ProcessingControl
{
	#[allow(missing_docs)]
	Brightness = 1 << 0,
	
	#[allow(missing_docs)]
	Contrast = 1 << 1,
	
	#[allow(missing_docs)]
	Hue = 1 << 2,
	
	#[allow(missing_docs)]
	Saturation = 1 << 3,
	
	#[allow(missing_docs)]
	Sharpness = 1 << 4,
	
	#[allow(missing_docs)]
	Gamma = 1 << 5,
	
	#[allow(missing_docs)]
	WhiteBalanceTemperature = 1 << 6,
	
	#[allow(missing_docs)]
	WhiteBalanceComponent = 1 << 7,
	
	#[allow(missing_docs)]
	BacklightCompensation = 1 << 8,
	
	#[allow(missing_docs)]
	Gain = 1 << 9,
	
	#[allow(missing_docs)]
	PowerLineFrequency = 1 << 10,
	
	#[allow(missing_docs)]
	AutomaticHue = 1 << 11,
	
	#[allow(missing_docs)]
	AutomaticWhiteBalanceTemperature = 1 << 12,
	
	#[allow(missing_docs)]
	AutomaticWhiteBalanceComponent = 1 << 13,
	
	/// Only for specification version 1.5 and later.
	AutomaticContrast = 1 << 18,
}
