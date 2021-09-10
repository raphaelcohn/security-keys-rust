// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// Extension code and controls.
#[derive(Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub enum ExtensionCodeAndControls
{
	/// Microsofot UVC 1.5 controls: <https://docs.microsoft.com/en-us/windows-hardware/drivers/stream/uvc-extensions-1-5>.
	Microsoft(ExtensionControls),
	
	/// Sourced from <https://sourceforge.net/p/libwebcam/code/ci/master/tree/uvcdynctrl/data/046d/logitech.xml>.
	///
	/// ? H.264 Device Interface specification 0.9e ?
	H264(ExtensionControls),
	
	/// Vimicro-based SIS DOP camera for enabled LED flash.
	///
	/// Sourced from <https://sourceforge.net/p/libwebcam/code/ci/master/tree/uvcdynctrl/data/a0c8/sisdop.xml>.
	VimicroSisDop(WrappedBitFlags<VimicroSisDopExtensionControls>),
	
	/// Sourced from <https://sourceforge.net/p/libwebcam/code/ci/master/tree/uvcdynctrl/data/046d/logitech.xml>.
	///
	/// Dates from prior to 2008.
	LogitechUserHardwareVersion1(WrappedBitFlags<LogitechUserHardwareVersion1ExtensionControl>),
	
	/// Sourced from <https://sourceforge.net/p/libwebcam/code/ci/master/tree/uvcdynctrl/data/046d/logitech.xml>.
	///
	/// Dates from prior to 2008.
	LogitechVideoPipeVersion1(WrappedBitFlags<LogitechVideoPipeVersion1ExtensionControl>),
	
	/// Sourced from <https://sourceforge.net/p/libwebcam/code/ci/master/tree/uvcdynctrl/data/046d/logitech.xml>.
	LogitechVideoPipeVersion3(WrappedBitFlags<LogitechVideoPipeVersion3ExtensionControl>),
	
	/// Sourced from <https://sourceforge.net/p/libwebcam/code/ci/master/tree/uvcdynctrl/data/046d/logitech.xml>.
	///
	/// Dates from prior to 2008.
	LogitechDeviceInformationVersion1(WrappedBitFlags<LogitechDeviceInformationVersion1ExtensionControl>),
	
	/// Sourced from <https://sourceforge.net/p/libwebcam/code/ci/master/tree/uvcdynctrl/data/046d/logitech.xml>.
	LogitechDeviceInformationVersion3(WrappedBitFlags<LogitechDeviceInformationVersion3ExtensionControl>),
	
	/// Sourced from <https://sourceforge.net/p/libwebcam/code/ci/master/tree/uvcdynctrl/data/046d/logitech.xml>.
	///
	/// Dates from prior to 2008.
	LogitechMotorVersion1(WrappedBitFlags<LogitechMotorVersion1ExtensionControl>),
	
	/// Sourced from <https://sourceforge.net/p/libwebcam/code/ci/master/tree/uvcdynctrl/data/046d/logitech.xml>.
	LogitechTestDebugVersion3(WrappedBitFlags<LogitechTestDebugVersion3ExtensionControl>),
	
	/// Sourced from <https://sourceforge.net/p/libwebcam/code/ci/master/tree/uvcdynctrl/data/046d/logitech.xml>.
	LogitechPeripheral(WrappedBitFlags<LogitechPeripheralExtensionControl>),
	
	/// Sourced from <https://sourceforge.net/p/libwebcam/code/ci/master/tree/uvcdynctrl/data/046d/logitech.xml>.
	///
	/// H.264 cameras.
	LogitechCodec(WrappedBitFlags<LogitechCodecExtensionControl>),
	
	/// Sourced from <https://sourceforge.net/p/libwebcam/code/ci/master/tree/uvcdynctrl/data/046d/logitech.xml>.
	///
	/// H.264 cameras.
	LogitechCodecExtended(WrappedBitFlags<LogitechCodecExtendedExtensionControl>),
	
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
		
		#[inline(always)]
		fn known_controls<T: BitFlag<Numeric=u64>>(constructor: impl FnOnce(WrappedBitFlags<T>) -> ExtensionCodeAndControls, controls: ExtensionControls) -> ExtensionCodeAndControls
		{
			constructor(ExtensionCodeAndControls::convert_known_controls(controls))
		}
		
		use ExtensionCodeAndControls::*;
		let extension_code = entity_body.universally_unique_identifier(entity_index::<4>());
		match extension_code
		{
			MS_CAMERA_CONTROL_XU => Microsoft(controls),
			
			GUID_UVCX_H264_XU => H264(controls),
			
			UVC_GUID_SIS_LED_HW_CONTROL => known_controls(VimicroSisDop, controls),
			
			UVC_GUID_LOGITECH_USER_HW_CONTROL_V1 => known_controls(LogitechUserHardwareVersion1, controls),
			
			UVC_GUID_LOGITECH_VIDEO_PIPE_V1 => known_controls(LogitechVideoPipeVersion1, controls),
			
			UVC_GUID_LOGITECH_VIDEO_PIPE_V3 => known_controls(LogitechVideoPipeVersion3, controls),
			
			UVC_GUID_LOGITECH_DEVICE_INFORMATION_V1 => known_controls(LogitechDeviceInformationVersion1, controls),
			
			UVC_GUID_LOGITECH_DEVICE_INFORMATION_V3 => known_controls(LogitechDeviceInformationVersion3, controls),
			
			UVC_GUID_LOGITECH_MOTOR_CONTROL_V1 => known_controls(LogitechMotorVersion1, controls),
			
			UVC_GUID_LOGITECH_TEST_DEBUG_V3 => known_controls(LogitechTestDebugVersion3, controls),
			
			UVC_GUID_LOGITECH_PERIPHERAL => known_controls(LogitechPeripheral, controls),
			
			UVC_GUID_LOGITECH_CODEC => known_controls(LogitechCodec, controls),
			
			UVC_GUID_LOGITECH_CODECEX => known_controls(LogitechCodecExtended, controls),
			
			_ => Other
			{
				extension_code,
			
				controls,
			},
		}
	}
	
	
	#[inline(always)]
	fn convert_known_controls<T: BitFlag<Numeric=u64>>(controls: ExtensionControls) -> WrappedBitFlags<T>
	{
		WrappedBitFlags::from_bits_truncate(controls.0)
	}
}
