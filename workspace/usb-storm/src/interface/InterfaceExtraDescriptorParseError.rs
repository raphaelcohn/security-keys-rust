// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// Descriptor parse error.
#[derive(Debug, Clone, PartialEq, Eq)]
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub enum InterfaceExtraDescriptorParseError
{
	/// Audio Control (AC).
	AudioControl(AudioControlInterfaceExtraDescriptorParseError),
	
	/// Audio Streaming (AS).
	AudioStreaming(AudioStreamingInterfaceExtraDescriptorParseError),
	
	/// Device Firmware Upgrade (DFU).
	DeviceFirmwareUpgrade(DeviceFirmwareUpgradeInterfaceExtraDescriptorParseError),
	
	/// Human Interface Device (HID).
	HumanInterfaceDevice(HumanInterfaceDeviceInterfaceExtraDescriptorParseError),
	
	/// Internet Printing Protocol (IPP)
	InternetPrintingProtocol(InternetPrintingProtocolInterfaceExtraDescriptorParseError),
	
	/// Smart Card (CCID).
	SmartCard(SmartCardInterfaceExtraDescriptorParseError),
}

impl Display for InterfaceExtraDescriptorParseError
{
	#[inline(always)]
	fn fmt(&self, f: &mut Formatter) -> fmt::Result
	{
		Debug::fmt(self, f)
	}
}

impl error::Error for InterfaceExtraDescriptorParseError
{
	#[inline(always)]
	fn source(&self) -> Option<&(dyn error::Error + 'static)>
	{
		use InterfaceExtraDescriptorParseError::*;
		
		match self
		{
			AudioControl(cause) => Some(cause),
			
			AudioStreaming(cause) => Some(cause),
			
			DeviceFirmwareUpgrade(cause) => Some(cause),
			
			HumanInterfaceDevice(cause) => Some(cause),
			
			InternetPrintingProtocol(cause) => Some(cause),
			
			SmartCard(cause) => Some(cause),
		}
	}
}

impl From<AudioControlInterfaceExtraDescriptorParseError> for InterfaceExtraDescriptorParseError
{
	#[inline(always)]
	fn from(cause: AudioControlInterfaceExtraDescriptorParseError) -> Self
	{
		InterfaceExtraDescriptorParseError::AudioControl(cause)
	}
}

impl From<AudioStreamingInterfaceExtraDescriptorParseError> for InterfaceExtraDescriptorParseError
{
	#[inline(always)]
	fn from(cause: AudioStreamingInterfaceExtraDescriptorParseError) -> Self
	{
		InterfaceExtraDescriptorParseError::AudioStreaming(cause)
	}
}

impl From<DeviceFirmwareUpgradeInterfaceExtraDescriptorParseError> for InterfaceExtraDescriptorParseError
{
	#[inline(always)]
	fn from(cause: DeviceFirmwareUpgradeInterfaceExtraDescriptorParseError) -> Self
	{
		InterfaceExtraDescriptorParseError::DeviceFirmwareUpgrade(cause)
	}
}

impl From<HumanInterfaceDeviceInterfaceExtraDescriptorParseError> for InterfaceExtraDescriptorParseError
{
	#[inline(always)]
	fn from(cause: HumanInterfaceDeviceInterfaceExtraDescriptorParseError) -> Self
	{
		InterfaceExtraDescriptorParseError::HumanInterfaceDevice(cause)
	}
}

impl From<InternetPrintingProtocolInterfaceExtraDescriptorParseError> for InterfaceExtraDescriptorParseError
{
	#[inline(always)]
	fn from(cause: InternetPrintingProtocolInterfaceExtraDescriptorParseError) -> Self
	{
		InterfaceExtraDescriptorParseError::InternetPrintingProtocol(cause)
	}
}

impl From<SmartCardInterfaceExtraDescriptorParseError> for InterfaceExtraDescriptorParseError
{
	#[inline(always)]
	fn from(cause: SmartCardInterfaceExtraDescriptorParseError) -> Self
	{
		InterfaceExtraDescriptorParseError::SmartCard(cause)
	}
}

impl From<InfallibleError> for InterfaceExtraDescriptorParseError
{
	#[inline(always)]
	fn from(_cause: InfallibleError) -> Self
	{
		unreachable!("UnsupportedInterfaceAdditionalDescriptorParser can not construct Infallible")
	}
}
