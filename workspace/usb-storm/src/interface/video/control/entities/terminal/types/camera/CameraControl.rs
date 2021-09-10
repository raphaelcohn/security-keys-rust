// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// A camera control.
#[derive(Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
#[bitflags]
#[repr(u32)]
pub enum CameraControl
{
	#[allow(missing_docs)]
	ScanningMode = 1 << 0,
	
	#[allow(missing_docs)]
	AutomaticExposureMode = 1 << 1,
	
	#[allow(missing_docs)]
	AutomaticExposurePriority = 1 << 2,
	
	#[allow(missing_docs)]
	AbsoluteExposureTime = 1 << 3,
	
	#[allow(missing_docs)]
	RelativeExposureTime = 1 << 4,
	
	#[allow(missing_docs)]
	AbsoluteFocus = 1 << 5,
	
	#[allow(missing_docs)]
	RelativeFocus = 1 << 6,
	
	#[allow(missing_docs)]
	AbsoluteIris = 1 << 7,
	
	#[allow(missing_docs)]
	RelativeIris = 1 << 8,
	
	#[allow(missing_docs)]
	AbsoluteZoom = 1 << 9,
	
	#[allow(missing_docs)]
	RelativeZoom = 1 << 10,
	
	#[allow(missing_docs)]
	AbsolutePanTilt = 1 << 11,
	
	#[allow(missing_docs)]
	RelativePanTilt = 1 << 12,
	
	#[allow(missing_docs)]
	AbsoluteRoll = 1 << 13,
	
	#[allow(missing_docs)]
	RelativeRoll = 1 << 14,
	
	#[allow(missing_docs)]
	AutomaticFocus = 1 << 17,
	
	#[allow(missing_docs)]
	Privacy = 1 << 18,
	
	/// Only for specification version 1.5 and later.
	SimpleFocus = 1 << 19,
	
	/// Only for specification version 1.5 and later.
	Window = 1 << 20,
	
	/// Only for specification version 1.5 and later.
	RegionOfInterest = 1 << 21,
}
