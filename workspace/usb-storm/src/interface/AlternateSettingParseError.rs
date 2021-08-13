// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// Interface descriptor parse error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AlternateSettingParseError
{
	#[allow(missing_docs)]
	WrongLength
	{
		interface_index: u8,
		
		alternate_setting_index: u8,
		
		bLength: u8
	},
	
	#[allow(missing_docs)]
	WrongDescriptorType
	{
		interface_index: u8,
		
		alternate_setting_index: u8,
		
		bDescriptorType: DescriptorType
	},
	
	#[allow(missing_docs)]
	TooManyEndPoints
	{
		interface_index: u8,
		
		alternate_setting_index: u8,
		
		bNumEndpoints: u8,
	},
	
	#[allow(missing_docs)]
	InterfaceNumberTooLarge
	{
		interface_index: u8,
		
		alternate_setting_index: u8,
		
		bInterfaceNumber: u8,
	},
	
	#[allow(missing_docs)]
	DuplicateAlternateSetting
	{
		interface_index: u8,
		
		alternate_setting_index: u8,
	},
	
	#[allow(missing_docs)]
	EndPointsPointerIsNullBuNumberOfEndPointsIsNotZero
	{
		interface_index: u8,
		
		alternate_setting_index: u8,
		
		bNumEndpoints: u8,
	},
	
	#[allow(missing_docs)]
	EndPointParse
	{
		cause: EndPointParseError,
		
		interface_index: u8,
		
		alternate_setting_index: u8,
	
		end_point_index: u8,
	},
	
	/// This can happen if the end point is repeated with two different directions.
	DuplicateEndPointNumber
	{
		#[allow(missing_docs)]
		interface_index: u8,
		
		#[allow(missing_docs)]
		alternate_setting_index: u8,
		
		#[allow(missing_docs)]
		end_point_index: u8,
		
		#[allow(missing_docs)]
		end_point_number: EndPointNumber,
	},
	
	#[allow(missing_docs)]
	DescriptionString
	{
		cause: GetLocalizedStringError,
		
		interface_index: u8,
		
		alternate_setting_index: u8,
	},
	
	#[allow(missing_docs)]
	CouldNotParseAlternateSettingAdditionalDescriptor
	{
		cause: DescriptorParseError<InterfaceAdditionalDescriptorParseError>,
		
		interface_index: u8,
		
		alternate_setting_index: u8,
	},
	
	#[allow(missing_docs)]
	CouldNotAllocateMemoryForEndPoints(TryReserveError),
}

impl Display for AlternateSettingParseError
{
	#[inline(always)]
	fn fmt(&self, f: &mut Formatter) -> fmt::Result
	{
		Debug::fmt(self, f)
	}
}

impl error::Error for AlternateSettingParseError
{
	#[inline(always)]
	fn source(&self) -> Option<&(dyn error::Error + 'static)>
	{
		use AlternateSettingParseError::*;
		
		match self
		{
			EndPointParse { cause, .. } => Some(cause),
			
			DescriptionString { cause, .. } => Some(cause),
			
			CouldNotParseAlternateSettingAdditionalDescriptor { cause, .. } => Some(cause),
			
			CouldNotAllocateMemoryForEndPoints(cause) => Some(cause),
			
			_ => None,
		}
	}
}
