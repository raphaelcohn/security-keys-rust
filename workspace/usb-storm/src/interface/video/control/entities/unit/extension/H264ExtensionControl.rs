// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// H.264 extension controls.
///
/// See 'USB_Video_Payload_H 264_1.0.pdf', Section 3.3.
#[derive(Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
#[bitflags]
#[repr(u64)]
pub enum H264ExtensionControl
{
	/// `UVCX_VIDEO_CONFIG_PROBE`.
	VideoConfigurationProbe = 1 << 0,

	/// `UVCX_VIDEO_CONFIG_COMMIT`.
	VideoConfigurationCommit = 1 << 1,

	/// `UVCX_RATE_CONTROL_MODE`.
	RateControlMode = 1 << 2,

	/// `UVCX_TEMPORAL_SCALE_MODE`.
	TemporalScaleMode = 1 << 3,

	/// `UVCX_SPATIAL_SCALE_MODE`.
	SpatialScaleMode = 1 << 4,

	/// `UVCX_SNR_SCALE_MODE`.
	SignalToNoiseRatioScaleMode = 1 << 5,

	/// `UVCX_LTR_BUFFER_SIZE_CONTROL`.
	LtrBufferSize = 1 << 6,

	/// `UVCX_LTR_PICTURE_CONTROL`.
	LtrPicture = 1 << 7,

	/// `UVCX_PICTURE_TYPE_CONTROL`.
	PictureType = 1 << 8,

	/// `UVCX_VERSION`.
	Version = 1 << 9,

	/// `UVCX_ENCODER_RESET`.
	EncoderReset = 1 << 10,

	/// `UVCX_FRAMERATE_CONFIG`.
	FrameRateConfiguration = 1 << 11,

	/// `UVCX_VIDEO_ADVANCE_CONFIG`.
	VideoAdvanceConfiguration = 1 << 12,

	/// `UVCX_BITRATE_LAYERS`.
	BitRateLayers = 1 << 13,

	/// `UVCX_QP_STEPS_LAYERS`.
	QpStepsLayers = 1 << 14,
}
