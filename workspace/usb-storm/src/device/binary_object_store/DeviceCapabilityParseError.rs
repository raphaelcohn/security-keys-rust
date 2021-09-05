// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// A parse error.
#[derive(Debug, Clone, Eq, PartialEq)]
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub enum DeviceCapabilityParseError
{
	#[allow(missing_docs)]
	DescriptorTooShort
	{
		remaining_length: usize,
	},
	
	#[allow(missing_docs)]
	DescriptorTypeWasInvalid
	{
		bDescriptorType: u8,
	},
	
	#[allow(missing_docs)]
	BLengthTooShort
	{
		bLength: u8,
	},
	
	#[allow(missing_docs)]
	BLengthTooLong
	{
		bLength: u8,
	},
	
	#[allow(missing_docs)]
	ParseWirelessUsbDeviceCapability(#[serde(with = "TryReserveErrorRemote")] TryReserveError),
	
	#[allow(missing_docs)]
	ParseUsb2ExtensionDeviceCapability(Usb2ExtensionDeviceCapabilityParseError),
	
	#[allow(missing_docs)]
	ParseSuperSpeedDeviceCapability(SuperSpeedDeviceCapabilityParseError),
	
	#[allow(missing_docs)]
	ParseContainerIdentifierDeviceCapability(ContainerIdentifierDeviceCapabilityParseError),
	
	#[allow(missing_docs)]
	ParsePlatformDeviceCapability(PlatformDeviceCapabilityParseError),
	
	#[allow(missing_docs)]
	ParsePowerDeliveryDeviceCapability(#[serde(with = "TryReserveErrorRemote")] TryReserveError),
	
	#[allow(missing_docs)]
	ParseBatteryInformationDeviceCapability(#[serde(with = "TryReserveErrorRemote")] TryReserveError),
	
	#[allow(missing_docs)]
	PowerDeliveryConsumerPortDeviceCapability(#[serde(with = "TryReserveErrorRemote")] TryReserveError),
	
	#[allow(missing_docs)]
	PowerDeliveryProducerPortDeviceCapability(#[serde(with = "TryReserveErrorRemote")] TryReserveError),
	
	#[allow(missing_docs)]
	ParseSuperSpeedPlusDeviceCapability(SuperSpeedPlusDeviceCapabilityParseError),
	
	#[allow(missing_docs)]
	ParseWirelessUsbExtendedDeviceCapability(#[serde(with = "TryReserveErrorRemote")] TryReserveError),
	
	#[allow(missing_docs)]
	ParseBillboardDeviceCapability(BillboardDeviceCapabilityParseError),
	
	#[allow(missing_docs)]
	ParseAuthenticationDeviceCapability(#[serde(with = "TryReserveErrorRemote")] TryReserveError),
	
	#[allow(missing_docs)]
	ParseBillboardAlternateModeDeviceCapability(BillboardAlternateModeDeviceCapabilityParseError),
	
	#[allow(missing_docs)]
	ParseConfigurationSummaryDeviceCapability(ConfigurationSummaryDeviceCapabilityParseError),
	
	#[allow(missing_docs)]
	ParseReservedDeviceCapability(#[serde(with = "TryReserveErrorRemote")] TryReserveError),
}

impl Display for DeviceCapabilityParseError
{
	#[inline(always)]
	fn fmt(&self, f: &mut Formatter) -> fmt::Result
	{
		Debug::fmt(self, f)
	}
}

impl error::Error for DeviceCapabilityParseError
{
	#[inline(always)]
	fn source(&self) -> Option<&(dyn error::Error + 'static)>
	{
		use DeviceCapabilityParseError::*;
		
		match self
		{
			ParseWirelessUsbDeviceCapability(cause) => Some(cause),
			
			ParseUsb2ExtensionDeviceCapability(cause) => Some(cause),
			
			ParseSuperSpeedDeviceCapability(cause) => Some(cause),
			
			ParseContainerIdentifierDeviceCapability(cause) => Some(cause),
			
			ParsePlatformDeviceCapability(cause) => Some(cause),
			
			ParsePowerDeliveryDeviceCapability(cause) => Some(cause),
			
			ParseBatteryInformationDeviceCapability(cause) => Some(cause),
			
			PowerDeliveryConsumerPortDeviceCapability(cause) => Some(cause),
			
			PowerDeliveryProducerPortDeviceCapability(cause) => Some(cause),
			
			ParseSuperSpeedPlusDeviceCapability(cause) => Some(cause),
			
			ParseWirelessUsbExtendedDeviceCapability(cause) => Some(cause),
			
			ParseBillboardDeviceCapability(cause) => Some(cause),
			
			ParseAuthenticationDeviceCapability(cause) => Some(cause),
			
			ParseBillboardAlternateModeDeviceCapability(cause) => Some(cause),
			
			ParseConfigurationSummaryDeviceCapability(cause) => Some(cause),
			
			ParseReservedDeviceCapability(cause) => Some(cause),
			
			_ => None,
		}
	}
}

impl From<Usb2ExtensionDeviceCapabilityParseError> for DeviceCapabilityParseError
{
	#[inline(always)]
	fn from(cause: Usb2ExtensionDeviceCapabilityParseError) -> Self
	{
		DeviceCapabilityParseError::ParseUsb2ExtensionDeviceCapability(cause)
	}
}

impl From<SuperSpeedDeviceCapabilityParseError> for DeviceCapabilityParseError
{
	#[inline(always)]
	fn from(cause: SuperSpeedDeviceCapabilityParseError) -> Self
	{
		DeviceCapabilityParseError::ParseSuperSpeedDeviceCapability(cause)
	}
}

impl From<ContainerIdentifierDeviceCapabilityParseError> for DeviceCapabilityParseError
{
	#[inline(always)]
	fn from(cause: ContainerIdentifierDeviceCapabilityParseError) -> Self
	{
		DeviceCapabilityParseError::ParseContainerIdentifierDeviceCapability(cause)
	}
}

impl From<PlatformDeviceCapabilityParseError> for DeviceCapabilityParseError
{
	#[inline(always)]
	fn from(cause: PlatformDeviceCapabilityParseError) -> Self
	{
		DeviceCapabilityParseError::ParsePlatformDeviceCapability(cause)
	}
}

impl From<SuperSpeedPlusDeviceCapabilityParseError> for DeviceCapabilityParseError
{
	#[inline(always)]
	fn from(cause: SuperSpeedPlusDeviceCapabilityParseError) -> Self
	{
		DeviceCapabilityParseError::ParseSuperSpeedPlusDeviceCapability(cause)
	}
}

impl From<BillboardDeviceCapabilityParseError> for DeviceCapabilityParseError
{
	#[inline(always)]
	fn from(cause: BillboardDeviceCapabilityParseError) -> Self
	{
		DeviceCapabilityParseError::ParseBillboardDeviceCapability(cause)
	}
}

impl From<BillboardAlternateModeDeviceCapabilityParseError> for DeviceCapabilityParseError
{
	#[inline(always)]
	fn from(cause: BillboardAlternateModeDeviceCapabilityParseError) -> Self
	{
		DeviceCapabilityParseError::ParseBillboardAlternateModeDeviceCapability(cause)
	}
}

impl From<ConfigurationSummaryDeviceCapabilityParseError> for DeviceCapabilityParseError
{
	#[inline(always)]
	fn from(cause: ConfigurationSummaryDeviceCapabilityParseError) -> Self
	{
		DeviceCapabilityParseError::ParseConfigurationSummaryDeviceCapability(cause)
	}
}
