// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// An USB 3.0 concept.
#[derive(Debug, Clone, Eq, PartialEq, PartialOrd, Ord, Hash)]
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub enum DeviceCapability
{
	/// Wireless USB
	WirelessUsb(Vec<u8>),
	
	/// USB 2.0 Extension.
	Usb2Extension(Usb2ExtensionDeviceCapability),
	
	/// SuperSpeed.
	SuperSpeed(SuperSpeedDeviceCapability),
	
	/// Container Identifier.
	ContainerIdentifier(ContainerIdentifierDeviceCapability),
	
	/// Platform.
	Platform(PlatformDeviceCapability),
	
	/// Power Delivery (PD).
	PowerDelivery(Vec<u8>),
	
	/// Battery information.
	BatteryInformation(Vec<u8>),
	
	/// Power Delivery (PD) consumer port.
	PowerDeliveryConsumerPort(Vec<u8>),
	
	/// Power Delivery (PD) provider port.
	PowerDeliveryProviderPort(Vec<u8>),
	
	/// SuperSpeed Plus.
	SuperSpeedPlus(SuperSpeedPlusDeviceCapability),
	
	/// Precision time measurement.
	PrecisionTimeMeasurement,
	
	/// Wireless USB extended.
	WirelessUsbExtended(Vec<u8>),
	
	/// Billboard.
	Billboard(BillboardDeviceCapability),
	
	/// Authentication.
	Authentication(Vec<u8>),
	
	/// Billboard alternate mode.
	BillboardAlternateMode(BillboardAlternateModeDeviceCapability),
	
	/// Configuration summary.
	ConfigurationSummary(ConfigurationSummaryDeviceCapability),
	
	/// Reserved.
	Reserved(ReservedDeviceCapability),
}

impl DeviceCapability
{
	const DeviceCapabilityHeaderSize: usize = DescriptorHeaderLength + 1;
	
	#[inline(always)]
	fn parse(device_capabilities_bytes: &[u8], device_connection: &DeviceConnection, has_microsoft_operating_system_descriptors_version_2_0: &mut bool) -> Result<DeadOrAlive<(usize, DeviceCapability)>, DeviceCapabilityParseError>
	{
		use DeviceCapability::*;
		use DeviceCapabilityParseError::*;
		
		let remaining_length = device_capabilities_bytes.len();
		
		if unlikely!(remaining_length < Self::DeviceCapabilityHeaderSize)
		{
			return Err(DescriptorTooShort { remaining_length })
		}
		
		let bDescriptorType = device_capabilities_bytes.u8(1);
		
		if unlikely!(bDescriptorType != 0x10)
		{
			return Err(DescriptorTypeWasInvalid { bDescriptorType })
		}
		
		let bLength = device_capabilities_bytes.u8(0);
		let length = bLength as usize;
		if unlikely!(length < Self::DeviceCapabilityHeaderSize)
		{
			return Err(BLengthTooShort { bLength })
		}
		if unlikely!(length > remaining_length)
		{
			return Err(BLengthTooLong { bLength })
		}
		
		let bDevCapabilityType = device_capabilities_bytes.u8(DescriptorHeaderLength);
		let device_capability_bytes = device_capabilities_bytes.get_unchecked_range_safe(Self::DeviceCapabilityHeaderSize .. length);
		let device_capability = match bDevCapabilityType
		{
			0x01 => WirelessUsb(Self::parse_blob(device_capability_bytes, ParseWirelessUsbDeviceCapability)?),
			
			0x02 => Usb2Extension(Usb2ExtensionDeviceCapability::parse(device_capability_bytes)?),
			
			0x03 => SuperSpeed(SuperSpeedDeviceCapability::parse(device_capability_bytes)?),
			
			0x04 => ContainerIdentifier(ContainerIdentifierDeviceCapability::parse(device_capability_bytes)?),
			
			0x05 =>
			{
				let dead_or_alive = PlatformDeviceCapability::parse(device_capability_bytes, device_connection, has_microsoft_operating_system_descriptors_version_2_0)?;
				Platform(return_ok_if_dead!(dead_or_alive))
			},
			
			0x06 => PowerDelivery(Self::parse_blob(device_capability_bytes, ParsePowerDeliveryDeviceCapability)?),
			
			0x07 => BatteryInformation(Self::parse_blob(device_capability_bytes, ParseBatteryInformationDeviceCapability)?),
			
			0x08 => PowerDeliveryConsumerPort(Self::parse_blob(device_capability_bytes, PowerDeliveryConsumerPortDeviceCapability)?),
			
			0x09 => PowerDeliveryProviderPort(Self::parse_blob(device_capability_bytes, PowerDeliveryProducerPortDeviceCapability)?),
			
			0x0A => SuperSpeedPlus(SuperSpeedPlusDeviceCapability::parse(device_capability_bytes)?),
			
			0x0B => PrecisionTimeMeasurement,
			
			0x0C => WirelessUsbExtended(Self::parse_blob(device_capability_bytes, ParseWirelessUsbExtendedDeviceCapability)?),
			
			0x0D =>
			{
				let dead_or_alive = BillboardDeviceCapability::parse(device_capability_bytes, device_connection)?;
				Billboard(return_ok_if_dead!(dead_or_alive))
			},
			
			0x0E => Authentication(Self::parse_blob(device_capability_bytes, ParseAuthenticationDeviceCapability)?),
			
			0x0F => BillboardAlternateMode(BillboardAlternateModeDeviceCapability::parse(device_capability_bytes)?),
			
			0x10 => ConfigurationSummary(ConfigurationSummaryDeviceCapability::parse(device_capability_bytes)?),
			
			0x00 | 0x11 ..= 0xFF => Reserved(ReservedDeviceCapability::parse(bDescriptorType, device_capability_bytes).map_err(ParseReservedDeviceCapability)?),
		};
		
		Ok(Alive((length, device_capability)))
	}
	
	#[inline(always)]
	fn parse_blob(device_capability_bytes: &[u8], error: impl FnOnce(TryReserveError) -> DeviceCapabilityParseError) -> Result<Vec<u8>, DeviceCapabilityParseError>
	{
		Vec::new_from(device_capability_bytes).map_err(error)
	}
}
