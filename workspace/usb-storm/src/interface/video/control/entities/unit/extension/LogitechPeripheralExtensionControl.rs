// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// Logitech codec extension controls.
#[derive(Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
#[bitflags]
#[repr(u64)]
pub enum LogitechPeripheralExtensionControl
{
	/// `XU_PERIPHERALCONTROL_PANTILT_RELATIVE_CONTROL`.
	RegisterAddress = 1 << 0,

	/// `XU_PERIPHERALCONTROL_PANTILT_MODE_CONTROL`.
	RegisterAccess = 1 << 1,
	
	/// `XU_PERIPHERALCONTROL_MAXIMUM_RESOLUTION_SUPPORT_FOR_PANTILT_CONTROL`.
	EepromAddress = 1 << 2,
	
	/// `XU_PERIPHERALCONTROL_AF_MOTORCONTROL`.
	AutofocusMotor = 1 << 3,
	
	/// `XU_PERIPHERALCONTROL_AF_BLOB_CONTROL`.
	AutofocusBlob = 1 << 4,
	
	/// `XU_PERIPHERALCONTROL_AF_VCM_PARAMETERS`.
	AutofocusVcmParameters = 1 << 5,
	
	/// `XU_PERIPHERALCONTROL_AF_STATUS`.
	AutofocusStatus = 1 << 6,
	
	/// `XU_PERIPHERALCONTROL_AF_THRESHOLDS`.
	AutofocusThresholds = 1 << 7,
	
	/// `XU_PERIPHERALCONTROL_LED`.
	Led = 1 << 8,
	
	/// `XU_PERIPHERAL_CONTROL_PERIPHERAL_STATUS`.
	PeripheralStatus = 1 << 9,
	
	/// `XU_PERIPHERAL_CONTROL_SPEAKER_VOLUME`.
	SpeakerVOlume = 1 << 10,
	
	/// `XU_PERIPHERAL_CONTROL_DEVICE_CODEC_STATUS`.
	DeviceCodecStatus = 1 << 11,
	
	/// `XU_PERIPHERAL_CONTROL_SPEAKER`.
	Speaker = 1 << 12,

}
