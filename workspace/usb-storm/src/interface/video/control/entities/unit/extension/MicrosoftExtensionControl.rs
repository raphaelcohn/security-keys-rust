// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// Microsofot UVC 1.5 extension controls.
///
/// See <https://docs.microsoft.com/en-us/windows-hardware/drivers/stream/uvc-extensions-1-5>.
#[derive(Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
#[bitflags]
#[repr(u64)]
pub enum MicrosoftExtensionControl
{
	/// `MSXU_CONTROL_FOCUS`.
	Focus = 1 << 0,

	/// `MSXU_CONTROL_EXPOSURE`.
	Exposure = 1 << 1,

	/// `MSXU_CONTROL_EVCOMPENSATION`.
	ExposureValueCompension = 1 << 2,

	/// `MSXU_CONTROL_WHITEBALANCE`.
	WhiteBalance = 1 << 3,
	
	/// `MSXU_CONTROL_FACE_AUTHENTICATION`.
	FaceAuthentication = 1 << 5,

	/// `MSXU_CONTROL_CAMERA_EXTRINSICS`.
	CameraExtrinsics = 1 << 6,

	/// `MSXU_CONTROL_CAMERA_INTRINSICS`.
	CameraIntrinsics = 1 << 7,

	/// `MSXU_CONTROL_METADATA`.
	Metadata = 1 << 8,

	/// `MSXU_CONTROL_IR_TORCH`.
	InfraRedTorch = 1 << 9,

	/// `MSXU_CONTROL_DIGITALWINDOW`.
	DigitalWindow = 1 << 10,

	/// `MSXU_CONTROL_DIGITALWINDOW_CONFIG`.
	DigitalWindowConfiguration = 1 << 11,

	/// `MSXU_CONTROL_VIDEO_HDR`.
	VideoHighDynamicRange = 1 << 12,
}
