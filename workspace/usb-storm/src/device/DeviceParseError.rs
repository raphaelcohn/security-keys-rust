// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// Device descriptor parse error.
#[derive(Debug, Clone, PartialEq, Eq)]
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub enum DeviceParseError
{
	#[allow(missing_docs)]
	CouldNotAllocateMemoryForConfigurations(#[serde(with = "TryReserveErrorRemote")] TryReserveError),
	
	#[allow(missing_docs)]
	ParentLocation(LocationError),
	
	#[allow(missing_docs)]
	DeviceHandleOpen(DeviceHandleOpenError),
	
	#[allow(missing_docs)]
	GetLanguages(GetLanguagesError),
	
	#[allow(missing_docs)]
	GetBinaryObjectStore(BinaryObjectStoreParseError),
	
	#[allow(missing_docs)]
	MaximumSupportedUsbVersion(VersionParseError),
	
	#[allow(missing_docs)]
	MicrosoftOperatingSystemDescriptorStringVersion_1_0_VendorCode(GetLocalizedUtf16LittleEndianStringError),
	
	#[allow(missing_docs)]
	FirmwareVersion(VersionParseError),
	
	#[allow(missing_docs)]
	ManufacturerString(GetLocalizedStringError),
	
	#[allow(missing_docs)]
	ProductNameString(GetLocalizedStringError),
	
	#[allow(missing_docs)]
	SerialNumberString(GetLocalizedStringError),
	
	#[allow(missing_docs)]
	GetConfigurationDescriptor
	{
		cause: GetConfigurationDescriptorBackendError,
		
		configuration_index: u3,
	},
	
	#[allow(missing_docs)]
	ParseConfigurationDescriptor
	{
		cause: ConfigurationParseError,
		
		configuration_index: u3,
	},
	
	#[allow(missing_docs)]
	DuplicateConfigurationNumber
	{
		configuration_index: u3,
		
		configuration_number: ConfigurationNumber,
	},
	
	#[allow(missing_docs)]
	GetActiveConfigurationDescriptor(GetConfigurationDescriptorBackendError),
	
	#[allow(missing_docs)]
	ParseConfigurationNumberOfActiveConfigurationDescriptor(ConfigurationParseError),

	#[allow(missing_docs)]
	TooManyConfigurations
	{
		bNumConfigurations: u8,
	},
	
	#[allow(missing_docs)]
	CouldNotAllocateMemoryForLanguages(#[serde(with = "TryReserveErrorRemote")] TryReserveError),
	
	#[allow(missing_docs)]
	HubDescriptorParse(HubDescriptorParseError),
}

impl Display for DeviceParseError
{
	#[inline(always)]
	fn fmt(&self, f: &mut Formatter) -> fmt::Result
	{
		Debug::fmt(self, f)
	}
}

impl error::Error for DeviceParseError
{
	#[inline(always)]
	fn source(&self) -> Option<&(dyn error::Error + 'static)>
	{
		use DeviceParseError::*;
		
		match self
		{
			DeviceHandleOpen(cause) => Some(cause),
			
			GetLanguages(cause) => Some(cause),
			
			GetBinaryObjectStore(cause) => Some(cause),
			
			MaximumSupportedUsbVersion(cause) => Some(cause),
			
			MicrosoftOperatingSystemDescriptorStringVersion_1_0_VendorCode(cause) => Some(cause),
			
			FirmwareVersion(cause) => Some(cause),
			
			ManufacturerString(cause) => Some(cause),
			
			ProductNameString(cause) => Some(cause),
			
			SerialNumberString(cause) => Some(cause),
			
			GetConfigurationDescriptor { cause, .. } => Some(cause),
			
			ParseConfigurationDescriptor { cause, .. } => Some(cause),
			
			GetActiveConfigurationDescriptor(cause) => Some(cause),
			
			ParseConfigurationNumberOfActiveConfigurationDescriptor(cause) => Some(cause),
			
			CouldNotAllocateMemoryForLanguages(cause) => Some(cause),
			
			CouldNotAllocateMemoryForConfigurations(cause) => Some(cause),
			
			ParentLocation(cause) => Some(cause),
			
			HubDescriptorParse(cause) => Some(cause),
			
			_ => None,
		}
	}
}

impl From<DeviceHandleOpenError> for DeviceParseError
{
	#[inline(always)]
	fn from(cause: DeviceHandleOpenError) -> DeviceParseError
	{
		DeviceParseError::DeviceHandleOpen(cause)
	}
}

impl From<BinaryObjectStoreParseError> for DeviceParseError
{
	#[inline(always)]
	fn from(cause: BinaryObjectStoreParseError) -> DeviceParseError
	{
		DeviceParseError::GetBinaryObjectStore(cause)
	}
}

impl From<HubDescriptorParseError> for DeviceParseError
{
	#[inline(always)]
	fn from(cause: HubDescriptorParseError) -> DeviceParseError
	{
		DeviceParseError::HubDescriptorParse(cause)
	}
}
