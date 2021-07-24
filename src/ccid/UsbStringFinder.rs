// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


enum UsbStringFinder<T: UsbContext>
{
	Opened
	{
		device_handle: DeviceHandle<T>,
	
		languages: Vec<Language>,
	},
	
	FailedToOpenDeviceHandle,
}

impl<T: UsbContext> UsbStringFinder<T>
{
	const TimeOut: Duration = Duration::from_secs(5);
	
	#[inline(always)]
	fn new(device: &Device<T>) -> Result<Self, UsbError>
	{
		use self::UsbStringFinder::*;
		
		match device.open()
		{
			Err(_) => Ok(FailedToOpenDeviceHandle),
			
			Ok(device_handle) =>
			{
				let languages = device_handle.read_languages(Self::TimeOut).map_err(UsbError::GetDeviceLanguages)?;
				Ok
				(
					Opened
					{
						device_handle,
					
						languages,
					}
				)
			}
		}
	}
	
	#[inline(always)]
	fn find(&self, index: Option<u8>) -> Result<Option<UsbStringOrIndex>, UsbError>
	{
		use self::UsbStringFinder::*;
		use self::UsbStringOrIndex::*;
		
		match index
		{
			None => Ok(None),
		
			Some(index) => match self
			{
				Opened { device_handle, languages } => Ok(Some(HaveString(UsbString::read(index, device_handle, languages)?))),
				
				FailedToOpenDeviceHandle => Ok(Some(CouldNotOpenDeviceHandle { index })),
			},
		}
	}
	
	#[inline(always)]
	fn into_languages(self) -> Option<Vec<UsbLanguage>>
	{
		use self::UsbStringFinder::*;
		
		match self
		{
			Opened { languages, .. } => Some(UsbLanguage::convert_languages(languages)),
			
			FailedToOpenDeviceHandle => None,
		}
	}
}
