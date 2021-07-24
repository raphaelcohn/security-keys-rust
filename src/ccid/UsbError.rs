// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// USB (rusb) errors.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub(crate) enum UsbError
{
	ListDevices(rusb::Error),
	
	GetDevicePortNumbers(rusb::Error),
	
	GetDeviceDescriptor(rusb::Error),
	
	GetDeviceActiveConfigDescriptor(rusb::Error),
	
	GetDeviceLanguages(rusb::Error),
	
	GetDeviceConfigurationDescriptor
	{
		cause: rusb::Error,
		
		configuration_descriptor_index: u8,
	},

	OpenDevice
	{
		cause: rusb::Error,
		
		bus_number: u8,
		
		address: u8,
		
		port_number: u8,
	},
	
	CouldNotReadString
	{
		cause: rusb::Error,
		
		language: Language,
		
		index: u8,
	},

	ActiveConfigurationNotInConfiguations,
	
	InvalidCcidDeviceDescriptor(&'static str),
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
			
			GetDevicePortNumbers(cause) => Some(cause),
			
			GetDeviceDescriptor(cause) => Some(cause),
			
			GetDeviceActiveConfigDescriptor(cause) => Some(cause),
			
			GetDeviceLanguages(cause) => Some(cause),
			
			GetDeviceConfigurationDescriptor { cause, .. } => Some(cause),
			
			OpenDevice { cause, .. } => Some(cause),
			
			CouldNotReadString { cause, .. } => Some(cause),
			
			_ => None,
		}
	}
}
