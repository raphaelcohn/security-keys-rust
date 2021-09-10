// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// Extension code and controls.
#[derive(Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub enum ExtensionCodeAndControls
{
	/// Vimicro-based SIS DOP camera for enabled LED flash.
	///
	/// Sourced from <https://sourceforge.net/p/libwebcam/code/ci/master/tree/uvcdynctrl/data/a0c8/sisdop.xml>.
	VimicroSisLedFlash(ExtensionControls),
	
	/// Microsofot UVC 1.5 controls: <https://docs.microsoft.com/en-us/windows-hardware/drivers/stream/uvc-extensions-1-5>.
	Microsoft(ExtensionControls),
	
	/// Sourced from <https://sourceforge.net/p/libwebcam/code/ci/master/tree/uvcdynctrl/data/046d/logitech.xml>.
	///
	/// ? H.264 Device Interface specification 0.9e ?
	H264(ExtensionControls),
	
	/// Sourced from <https://sourceforge.net/p/libwebcam/code/ci/master/tree/uvcdynctrl/data/046d/logitech.xml>.
	///
	/// * Control 0 is LED elimination, blinking and blink frequency: `XU_HW_CONTROL_LED1`.
	LogitechUserHardwareVersion1(ExtensionControls),
	
	/// Sourced from <https://sourceforge.net/p/libwebcam/code/ci/master/tree/uvcdynctrl/data/046d/logitech.xml>.
	///
	/// * Control 4 is disable color processing: `XU_COLOR_PROCESSING_DISABLE`.
	/// * Control 7 is increase raw bits per pixel from 8 bits to 10 bits: `XU_RAW_DATA_BITS_PER_PIXEL`
	LogitechVideoPipeVersion1(ExtensionControls),
	
	/// Sourced from <https://sourceforge.net/p/libwebcam/code/ci/master/tree/uvcdynctrl/data/046d/logitech.xml>.
	///
	/// * Control 0 is color boost: `XU_VIDEO_COLOR_BOOST_CONTROL`.
	/// * Control 1 is native mode forced: `XU_VIDEO_NATIVE_MODE_FORCED_CONTROL`.
	/// * Control 2 is native mode automatic: `XU_VIDEO_NATIVE_MODE_AUTO_CONTROL`.
	/// * Control 3 is right-left mode automatic: `XU_VIDEO_RIGHTLIGHT_MODE_CONTROL`.
	/// * Control 4 is ?: `XU_VIDEO_RIGHTLIGHT_ZOI_CONTROL`.
	/// * Control 5 is : `XU_VIDEO_FW_ZOOM_CONTROL`.
	/// * Control 6 is : `XU_VIDEO_DUAL_ISO_ENABLE_CONTROL`.
	/// * Control 7 is : `XU_VIDEO_SENSOR_CROPPING_DIMENSION_CONTROL`.
	/// * Control 8 is : `XU_VIDEO_MJPEG_RESYNC_MARKER_CONTROL`.
	LogitechVideoPipeVersion3(ExtensionControls),
	
	/// Sourced from <https://sourceforge.net/p/libwebcam/code/ci/master/tree/uvcdynctrl/data/046d/logitech.xml>.
	///
	/// * Control 5 is information: `XU_USB_INFORMATION_CONTROL`.
	LogitechDeviceInformationVersion1(ExtensionControls),
	
	/// Sourced from <https://sourceforge.net/p/libwebcam/code/ci/master/tree/uvcdynctrl/data/046d/logitech.xml>.
	///
	/// * Control 0 is firmware version: `XU_FIRMWARE_VERSION_CONTROL`.
	/// * Control 1 is firmware CRC: `XU_FIRMWARE_CRC_CONTROL`.
	/// * Control 2 is EEPROM version: `XU_EEPROM_VERSION_CONTROL`.
	/// * Control 3 is sensor information: `XU_SENSOR_INFORMATION_CONTROL`.
	/// * Control 4 is processor information: `XU_PROCESSOR_INFORMATION_CONTROL`.
	/// * Control 5 is information: `XU_USB_INFORMATION_CONTROL`.
	/// * Control 8 is field-of-view: `XU_LENS_FOV_CONTROL`.
	/// * Control 9 is sensor dimension: `XU_SENSOR_DIMENSION_CONTROL`.
	/// * Control 10 is extended firmware version: `XU_EXTENDED_FIRMWARE_VERSION_CONTROL`.
	LogitechDeviceInformationVersion3(ExtensionControls),
	
	/// Sourced from <https://sourceforge.net/p/libwebcam/code/ci/master/tree/uvcdynctrl/data/046d/logitech.xml>.
	///
	/// * Control 0 is mechanical relative pan-and-tilt: `XU_MOTORCONTROL_PANTILT_RELATIVE`.
	/// * Control 1 is mechanical pan-and-tilt reset: `XU_MOTORCONTROL_PANTILT_RESET`.
	/// * Control 2 is mechanical motorized focus: `XU_MOTORCONTROL_FOCUS`.
	LogitechMotorVersion1(ExtensionControls),
	
	/// Sourced from <https://sourceforge.net/p/libwebcam/code/ci/master/tree/uvcdynctrl/data/046d/logitech.xml>.
	///
	/// * Control 0 is : `XU_TEST_REGISTER_ADDRESS_CONTROL`.
	/// * Control 1 is : `XU_TEST_REGISTER_ACCESS_CONTROL`.
	/// * Control 2 is : `XU_TEST_EEPROM_ADDRESS_CONTROL`.
	/// * Control 3 is : `XU_TEST_EEPROM_ACCESS_CONTROL`.
	/// * Control 4 is : `XU_TEST_SENSOR_ADDRESS_CONTROL`.
	/// * Control 5 is : `XU_TEST_SENSOR_ACCESS_CONTROL`.
	/// * Control 6 is : `XU_TEST_PERIPHERAL_MODE_CONTROL`.
	/// * Control 7 is : `XU_TEST_PERIPHERAL_OP_CONTROL`.
	/// * Control 8 is : `XU_TEST_PERIPHERAL_ACCESS_CONTROL`.
	/// * Control 9 is : `XU_TEST_TDE_MODE_CONTROL`.
	/// * Control 10 is : `XU_TEST_GAIN_CONTROL`.
	/// * Control 11 is : `XU_TEST_LOW_LIGHT_PRIORITY_CONTROL`.
	/// * Control 12 is : `XU_TEST_COLOR_PROCESSING_DISABLE_CONTROL`.
	/// * Control 13 is : `XU_TEST_PIXEL_DEFECT_CORRECTION_CONTROL`.
	/// * Control 14 is : `XU_TEST_LENS_SHADING_COMPENSATION_CONTROL`.
	/// * Control 15 is : `XU_TEST_GAMMA_CONTROL`.
	/// * Control 16 is : `XU_TEST_INTEGRATION_TIME_CONTROL`.
	/// * Control 17 is : `XU_TEST_RAW_DATA_BITS_PER_PIXEL_CONTROL`.
	/// * Control 18 is : `XU_TEST_ISP_ADDRESS_CONTROL`.
	/// * Control 19 is : `XU_TEST_ISP_ACCESS_CONTROL`.
	/// * Control 20 is : `XU_TEST_PERIPHERAL_ACCESS_EXT_CONTROL`.
	LogitechTestDebugVersion3(ExtensionControls),
	
	/// Sourced from <https://sourceforge.net/p/libwebcam/code/ci/master/tree/uvcdynctrl/data/046d/logitech.xml>.
	///
	/// * Control 0 is : `XU_PERIPHERALCONTROL_PANTILT_RELATIVE_CONTROL`.
	/// * Control 1 is : `XU_PERIPHERALCONTROL_PANTILT_MODE_CONTROL`.
	/// * Control 2 is : `XU_PERIPHERALCONTROL_MAXIMUM_RESOLUTION_SUPPORT_FOR_PANTILT_CONTROL`.
	/// * Control 3 is : `XU_PERIPHERALCONTROL_AF_MOTORCONTROL`.
	/// * Control 4 is : `XU_PERIPHERALCONTROL_AF_BLOB_CONTROL`.
	/// * Control 5 is : `XU_PERIPHERALCONTROL_AF_VCM_PARAMETERS`.
	/// * Control 5 is : `XU_PERIPHERALCONTROL_AF_VCM_PARAMETERS`.
	/// * Control 6 is : `XU_PERIPHERALCONTROL_AF_STATUS`.
	/// * Control 7 is : `XU_PERIPHERALCONTROL_AF_THRESHOLDS`.
	/// * Control 9 is : `XU_PERIPHERALCONTROL_LED`.
	/// * Control 8 is : `XU_PERIPHERAL_CONTROL_PERIPHERAL_STATUS`.
	/// * Control 10 is : `XU_PERIPHERAL_CONTROL_SPEAKER_VOLUME`.
	/// * Control 11 is : `XU_PERIPHERAL_CONTROL_DEVICE_CODEC_STATUS`.
	/// * Control 12 is : `XU_PERIPHERAL_CONTROL_SPEAKER`.
	LogitechPeripheral(ExtensionControls),
	
	/// Sourced from <https://sourceforge.net/p/libwebcam/code/ci/master/tree/uvcdynctrl/data/046d/logitech.xml>.
	///
	/// H.264 cameras.
	///
	/// * Control 0 is : `CXU_ENCODER_VIDEO_FORMAT_CONTROL`.
	/// * Control 1 is : `CXU_ENCODER_CONFIGURATION_CONTROL`.
	/// * Control 2 is : `CXU_RATE_CONTROL`.
	/// * Control 3 is : `CXU_FRAME_TYPE_CONTROL`.
	/// * Control 4 is : `CXU_CAMERA_DELAY`.
	/// * Control 5 is : `CXU_FILTER_CONTROL`.
	LogitechCodec(ExtensionControls),
	
	/// Sourced from <https://sourceforge.net/p/libwebcam/code/ci/master/tree/uvcdynctrl/data/046d/logitech.xml>.
	///
	/// H.264 cameras.
	///
	/// * Control 0 is : `CXXU_STATIC_CONTROL`.
	/// * Control 1 is : `CXXU_DYNAMIC_CONTROL`.
	/// * Control 2 is : `CXXU_ROI_CONTROL`.
	LogitechCodecExtended(ExtensionControls),
	
	/// Unrecognised identifier.
	Other
	{
		/// Extension code.
		extension_code: UniversallyUniqueIdentifier,
		
		/// Controls.
		controls: ExtensionControls,
	},
}

impl ExtensionCodeAndControls
{
	#[inline(always)]
	fn parse(entity_body: &[u8], controls: ExtensionControls) -> Self
	{
		const MS_CAMERA_CONTROL_XU: UniversallyUniqueIdentifier = UniversallyUniqueIdentifier::parse_microsoft_string_or_panic(b"{0F3F95DC-2632-4C4E-92C9-A04782F43BC8}");
		const GUID_UVCX_H264_XU: UniversallyUniqueIdentifier = UniversallyUniqueIdentifier::parse_rfc_4122_string_or_panic(b"A29E7641-DE04-47E3-8B2B-F4341AFF003B");
		const UVC_GUID_SIS_LED_HW_CONTROL: UniversallyUniqueIdentifier = UniversallyUniqueIdentifier::parse_rfc_4122_string_or_panic(b"5dc717a9-1941-da11-ae0e-000d56ac7b4c");
		const UVC_GUID_LOGITECH_USER_HW_CONTROL_V1: UniversallyUniqueIdentifier = UniversallyUniqueIdentifier::parse_rfc_4122_string_or_panic(b"63610682-5070-49ab-b8cc-b3855e8d221f");
		const UVC_GUID_LOGITECH_VIDEO_PIPE_V1: UniversallyUniqueIdentifier = UniversallyUniqueIdentifier::parse_rfc_4122_string_or_panic(b"63610682-5070-49ab-b8cc-b3855e8d2250");
		const UVC_GUID_LOGITECH_MOTOR_CONTROL_V1: UniversallyUniqueIdentifier = UniversallyUniqueIdentifier::parse_rfc_4122_string_or_panic(b"63610682-5070-49ab-b8cc-b3855e8d2256");
		const UVC_GUID_LOGITECH_DEVICE_INFORMATION_V1: UniversallyUniqueIdentifier = UniversallyUniqueIdentifier::parse_rfc_4122_string_or_panic(b"63610682-5070-49ab-b8cc-b3855e8d221e");
		const UVC_GUID_LOGITECH_DEVICE_INFORMATION_V3: UniversallyUniqueIdentifier = UniversallyUniqueIdentifier::parse_rfc_4122_string_or_panic(b"69678EE4-410F-40db-A850-7420D7D8240E");
		const UVC_GUID_LOGITECH_VIDEO_PIPE_V3: UniversallyUniqueIdentifier = UniversallyUniqueIdentifier::parse_rfc_4122_string_or_panic(b"49E40215-F434-47fe-B158-0E885023E51B");
		const UVC_GUID_LOGITECH_TEST_DEBUG_V3: UniversallyUniqueIdentifier = UniversallyUniqueIdentifier::parse_rfc_4122_string_or_panic(b"1F5D4CA9-DE11-4487-840D-50933C8EC8D1");
		const UVC_GUID_LOGITECH_PERIPHERAL: UniversallyUniqueIdentifier = UniversallyUniqueIdentifier::parse_rfc_4122_string_or_panic(b"FFE52D21-8030-4e2c-82D9-F587D00540BD");
		const UVC_GUID_LOGITECH_CODEC: UniversallyUniqueIdentifier = UniversallyUniqueIdentifier::parse_rfc_4122_string_or_panic(b"9ACD00B6-DC4A-4bbd-BDF8-5FFBB0C0D366");
		const UVC_GUID_LOGITECH_CODECEX: UniversallyUniqueIdentifier = UniversallyUniqueIdentifier::parse_rfc_4122_string_or_panic(b"49C532A0-4F15-4cfc-908A-5BCE154B1CEA");
		
		use ExtensionCodeAndControls::*;
		let extension_code = entity_body.universally_unique_identifier(entity_index::<4>());
		match extension_code
		{
			MS_CAMERA_CONTROL_XU => Microsoft(controls),
			
			UVC_GUID_SIS_LED_HW_CONTROL => VimicroSisLedFlash(controls),
			
			GUID_UVCX_H264_XU => H264(controls),
			
			UVC_GUID_LOGITECH_USER_HW_CONTROL_V1 => LogitechUserHardwareVersion1(controls),
			
			UVC_GUID_LOGITECH_VIDEO_PIPE_V1 => LogitechVideoPipeVersion1(controls),
			
			UVC_GUID_LOGITECH_VIDEO_PIPE_V3 => LogitechVideoPipeVersion3(controls),
			
			UVC_GUID_LOGITECH_DEVICE_INFORMATION_V1 => LogitechDeviceInformationVersion1(controls),
			
			UVC_GUID_LOGITECH_DEVICE_INFORMATION_V3 => LogitechDeviceInformationVersion3(controls),
			
			UVC_GUID_LOGITECH_MOTOR_CONTROL_V1 => LogitechMotorVersion1(controls),
			
			UVC_GUID_LOGITECH_TEST_DEBUG_V3 => LogitechTestDebugVersion3(controls),
			
			UVC_GUID_LOGITECH_PERIPHERAL => LogitechPeripheral(controls),
			
			UVC_GUID_LOGITECH_CODEC => LogitechCodec(controls),
			
			UVC_GUID_LOGITECH_CODECEX => LogitechCodecExtended(controls),
			
			_ => Other
			{
				extension_code,
			
				controls,
			},
		}
	}
}
