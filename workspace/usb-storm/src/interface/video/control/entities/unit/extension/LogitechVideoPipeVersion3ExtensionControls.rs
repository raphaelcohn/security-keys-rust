// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// Logitech video pipe version 3 extension controls.
#[derive(Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
#[bitflags]
#[repr(u64)]
pub enum LogitechVideoPipeVersion3ExtensionControl
{
	/// `XU_VIDEO_COLOR_BOOST_CONTROL`.
	ColorBoost = 1 << 0,
	
	/// `XU_VIDEO_NATIVE_MODE_FORCED_CONTROL`.
	ForcedNativeMode = 1 << 1,
	
	/// `XU_VIDEO_NATIVE_MODE_AUTO_CONTROL`.
	AutomaticNativeMode = 1 << 2,
	
	/// `XU_VIDEO_RIGHTLIGHT_MODE_CONTROL`.
	RightLightMode = 1 << 3,
	
	/// `XU_VIDEO_RIGHTLIGHT_ZOI_CONTROL`.
	RightLightZoi = 1 << 4,
	
	/// `XU_VIDEO_FW_ZOOM_CONTROL`.
	ForwardZoom = 1 << 5,
	
	/// `XU_VIDEO_DUAL_ISO_ENABLE_CONTROL`.
	DualIsoEnable = 1 << 6,
	
	/// `XU_VIDEO_SENSOR_CROPPING_DIMENSION_CONTROL`.
	SensorCroppingDimension = 1 << 7,
	
	/// `XU_VIDEO_MJPEG_RESYNC_MARKER_CONTROL`.
	MJpegResynchronizeMarker = 1 << 8,
}
