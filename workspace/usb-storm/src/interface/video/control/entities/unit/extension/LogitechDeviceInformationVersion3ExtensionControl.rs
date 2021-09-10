// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// Logitech device information version 3 extension controls.
#[derive(Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
#[bitflags]
#[repr(u64)]
pub enum LogitechDeviceInformationVersion3ExtensionControl
{
	/// `XU_FIRMWARE_VERSION_CONTROL`.
	FirmwareVersion = 1 << 0,

	/// `XU_FIRMWARE_CRC_CONTROL`.
	FirmwareCyclicRedundancyCheck = 1 << 1,

	/// `XU_EEPROM_VERSION_CONTROL`.
	EepromVersion = 1 << 2,

	/// `XU_SENSOR_INFORMATION_CONTROL`.
	SensorInformation = 1 << 3,

	/// `XU_PROCESSOR_INFORMATION_CONTROL`.
	ProcessorInformation = 1 << 4,

	/// `XU_USB_INFORMATION_CONTROL`.
	///
	/// cd `LogitechDeviceInformationVersion1ExtensionControl::UsbInformation`.
	UsbInformation = 1 << 5,

	// Controls 6 & 7 are not known.
	
	/// `XU_LENS_FOV_CONTROL`.
	LensFieldOfView = 1 << 8,

	/// `XU_SENSOR_DIMENSION_CONTROL`.
	SensorDimension = 1 << 9,

	/// `XU_EXTENDED_FIRMWARE_VERSION_CONTROL`.
	ExtendedFirmwareVersion = 1 << 10,
}
