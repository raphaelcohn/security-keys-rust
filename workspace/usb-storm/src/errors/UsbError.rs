// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// USB (rusb) errors.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UsbError
{
	#[allow(missing_docs)]
	ListDevices(rusb::Error),
	
	#[allow(missing_docs)]
	GetDeviceActiveConfigDescriptor(rusb::Error),
	
	#[allow(missing_docs)]
	GetDeviceConfigurationDescriptor
	{
		/// Cause.
		cause: rusb::Error,
		
		/// Which configuration descriptor could not be obtained.
		configuration_descriptor_index: u8,
	},
	
	#[allow(missing_docs)]
	OpenDevice
	{
		/// Cause.
		cause: rusb::Error,
		
		/// Bus number.
		bus_number: u8,
		
		/// Device address.
		address: u8,
		
		/// Device port number.
		port_number: u8,
	},
	
	#[allow(missing_docs)]
	CouldNotReadString
	{
		/// Cause.
		cause: rusb::Error,
		
		/// Language.
		language: Language,
		
		/// Index.
		index: u8,
	},
	
	#[allow(missing_docs)]
	CouldNotPushInterface(TryReserveError),
	
	#[allow(missing_docs)]
	CouldNotParseConfigurationAdditionalDescriptor(AdditionalDescriptorParseError<Infallible>),
	
	#[allow(missing_docs)]
	CouldNotParseInterfaceAdditionalDescriptor(AdditionalDescriptorParseError<InterfaceAdditionalDescriptorParseError>),
	
	#[allow(missing_docs)]
	CouldNotParseEndPointAdditionalDescriptor(AdditionalDescriptorParseError<Infallible>),
}

impl Display for UsbError
{
	#[inline(always)]
	fn fmt(&self, f: &mut Formatter) -> fmt::Result
	{
		Debug::fmt(self, f)
	}
}

impl error::Error for UsbError
{
	#[inline(always)]
	fn source(&self) -> Option<&(dyn error::Error + 'static)>
	{
		use self::UsbError::*;
		
		match self
		{
			ListDevices(cause) => Some(cause),
			
			DeviceUsbVersion(cause) => Some(cause),
			
			DeviceFirmwareVersion(cause) => Some(cause),
			
			GetDeviceActiveConfigDescriptor(cause) => Some(cause),
			
			GetDeviceConfigurationDescriptor { cause, .. } => Some(cause),
			
			OpenDevice { cause, .. } => Some(cause),
			
			CouldNotReadString { cause, .. } => Some(cause),
			
			NoInterfaces => None,
			
			CouldNotPushInterface(cause) => Some(cause),
			
			CouldNotParseConfigurationAdditionalDescriptor(cause) => Some(cause),
			
			CouldNotParseInterfaceAdditionalDescriptor(cause) => Some(cause),
			
			CouldNotParseEndPointAdditionalDescriptor(cause) => Some(cause),
		}
	}
}

impl From<AdditionalDescriptorParseError<InterfaceAdditionalDescriptorParseError>> for UsbError
{
	#[inline(always)]
	fn from(cause: AdditionalDescriptorParseError<InterfaceAdditionalDescriptorParseError>) -> Self
	{
		UsbError::CouldNotParseInterfaceAdditionalDescriptor(cause)
	}
}
