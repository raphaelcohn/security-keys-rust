// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// Logitech test debug version 3 extension controls.
#[derive(Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
#[bitflags]
#[repr(u64)]
pub enum LogitechTestDebugVersion3ExtensionControl
{
	/// `XU_TEST_REGISTER_ADDRESS_CONTROL`.
	RegisterAddress = 1 << 0,

	/// `XU_TEST_REGISTER_ACCESS_CONTROL`.
	RegisterAccess = 1 << 1,
	
	/// `XU_TEST_EEPROM_ADDRESS_CONTROL`.
	EepromAddress = 1 << 2,
	
	/// `XU_TEST_EEPROM_ACCESS_CONTROL`.
	EepromAccess = 1 << 3,
	
	/// `XU_TEST_SENSOR_ADDRESS_CONTROL`.
	SensorAddress = 1 << 4,
	
	/// `XU_TEST_SENSOR_ACCESS_CONTROL`.
	SensorAccess = 1 << 5,
	
	/// `XU_TEST_PERIPHERAL_MODE_CONTROL`.
	PeripheralMode = 1 << 6,
	
	/// `XU_TEST_PERIPHERAL_OP_CONTROL`.
	PeripheralOperation = 1 << 7,
	
	/// `XU_TEST_PERIPHERAL_ACCESS_CONTROL`.
	PeripheralAccess = 1 << 8,
	
	/// `XU_TEST_TDE_MODE_CONTROL`.
	TdeMode = 1 << 9,
	
	/// `XU_TEST_GAIN_CONTROL`.
	Gain = 1 << 10,
	
	/// `XU_TEST_LOW_LIGHT_PRIORITY_CONTROL`.
	LowLightPriority = 1 << 11,
	
	/// `XU_TEST_COLOR_PROCESSING_DISABLE_CONTROL`.
	///
	/// cf `LogitechVideoPipeVersion1ExtensionControl::DisableColorProcessing`.
	DisableColorProcessing = 1 << 12,
	
	/// `XU_TEST_PIXEL_DEFECT_CORRECTION_CONTROL`.
	PixelDefectCorrection = 1 << 13,
	
	/// `XU_TEST_LENS_SHADING_COMPENSATION_CONTROL`.
	LensShadingCompensation = 1 << 14,
	
	/// `XU_TEST_GAMMA_CONTROL`.
	Gamma = 1 << 15,
	
	/// `XU_TEST_INTEGRATION_TIME_CONTROL`.
	IntegrationTime = 1 << 16,
	
	/// `XU_TEST_RAW_DATA_BITS_PER_PIXEL_CONTROL`.
	///
	/// cf `LogitechVideoPipeVersion1ExtensionControl::IncreaseRawBitsPerPixelFrom8BitsTo10Bits`.
	IncreaseRawBitsPerPixelFrom8BitsTo10Bits = 1 << 17,
	
	/// `XU_TEST_ISP_ADDRESS_CONTROL`.
	IspAddress = 1 << 18,
	
	/// `XU_TEST_ISP_ACCESS_CONTROL`.
	IspAccess = 1 << 19,
	
	/// `XU_TEST_PERIPHERAL_ACCESS_EXT_CONTROL`.
	PeripheralAccessExtended = 1 << 20,

}
