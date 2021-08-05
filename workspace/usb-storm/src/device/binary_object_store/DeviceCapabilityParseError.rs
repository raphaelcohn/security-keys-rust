// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// A parse error.
#[derive(Debug, Clone, Eq, PartialEq)]
#[allow(missing_docs)]
pub enum DeviceCapabilityParseError
{
	DescriptorTooShort
	{
		remaining_length: usize,
	},
	
	DescriptorTypeWasInvalid
	{
		bDescriptorType: u8,
	},
	
	DescriptorWrongLength
	{
		bLength: u8,
	},
	
	ParseWirelessUsbDeviceCapability(TryReserveError),
	
	ParseUsb2ExtensionDeviceCapability(Usb2ExtensionDeviceCapabilityParseError),
	
	ParseSuperSpeedDeviceCapability(SuperSpeedDeviceCapabilityParseError),
	
	ParseContainerIdentifierDeviceCapability(ContainerIdentifierDeviceCapabilityParseError),
	
	ParsePlatformDeviceCapability(PlatformDeviceCapabilityParseError),
	
	ParsePowerDeliveryDeviceCapability(TryReserveError),
	
	ParseBatteryInformationDeviceCapability(TryReserveError),
	
	PowerDeliveryConsumerPortDeviceCapability(TryReserveError),
	
	PowerDeliveryProducerPortDeviceCapability(TryReserveError),
	
	ParseSuperSpeedPlusDeviceCapability(SuperSpeedPlusDeviceCapabilityParseError),
	
	ParseWirelessUsbExtendedDeviceCapability(TryReserveError),
	
	ParseBillboardDeviceCapability(TryReserveError),
	
	ParseAuthenticationDeviceCapability(TryReserveError),
	
	ParseBillboardExtendedDeviceCapability(TryReserveError),
	
	ParseConfigurationSummaryDeviceCapability(ConfigurationSummaryDeviceCapabilityParseError),
	
	ParseReservedDeviceCapability(TryReserveError),
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
			
			ParseBillboardExtendedDeviceCapability(cause) => Some(cause),
			
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

impl From<ConfigurationSummaryDeviceCapabilityParseError> for DeviceCapabilityParseError
{
	#[inline(always)]
	fn from(cause: ConfigurationSummaryDeviceCapabilityParseError) -> Self
	{
		DeviceCapabilityParseError::ParseConfigurationSummaryDeviceCapability(cause)
	}
}
