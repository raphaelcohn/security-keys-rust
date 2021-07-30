// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/raphaelcohn/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/raphaelcohn/security-keys-rust/master/COPYRIGHT.


/// Load driver error.
#[derive(Debug)]
#[allow(missing_docs)]
pub enum LoadDriverError
{
	CouldNotAllocateMemoryForOurDriverName(TryReserveError),
	
	CouldNotAllocateMemoryForUsbDetails(TryReserveError),
	
	ExecutableFolderPathDoesNotExist
	{
		executable_folder_path: PathBuf,
	},
	
	MissingBundleExecutableString,
	
	MissingCapabilitiesString,
	
	MissingVendorIdentifierArray,
	
	MissingProductIdentifierArray,
	
	MissingFriendlyNameArray,
	
	ProductIdentifiersArrayLengthDiffersToVendorIdentifiersArray,
	
	FriendlyNamesArrayLengthDiffersToVendorIdentifiersArray,
	
	CapabilitiesIsNot10Bytes,
	
	CapabilitiesIsNotHexadecimal(ParseNumberError),
	
	CapabilitiesBitFlagsAreUnknown(FromBitsError<DriverCapabilities>),
	
	VendorIdentifierIsNotAString,
	
	ProductIdentifierIsNotAString,
	
	FriendlyNameIsNotAString,
	
	VendorIdentifierStringIsNot6Bytes,
	
	VendorIdentifierIsNotHexadecimal(ParseNumberError),
	
	ProductIdentifierStringIsNot6Bytes,
	
	ProductIdentifierIsNotHexadecimal(ParseNumberError),
	
	LibraryFilePathIsNotAnExtantFile
	{
		library_file_path: PathBuf,
	},
	
	LoadLibrary(libloading::Error),
	
	GetSymbol
	{
		cause: libloading::Error,
	
		known_symbol_name: KnownSymbolName,
	},

	AdditionalInfoPListCheckFailed(&'static str),
}

impl From<libloading::Error> for LoadDriverError
{
	#[inline(always)]
	fn from(cause: libloading::Error) -> Self
	{
		LoadDriverError::LoadLibrary(cause)
	}
}

impl Display for LoadDriverError
{
	#[inline(always)]
	fn fmt(&self, f: &mut Formatter) -> fmt::Result
	{
		Debug::fmt(self, f)
	}
}

impl error::Error for LoadDriverError
{
	#[inline(always)]
	fn source(&self) -> Option<&(dyn error::Error + 'static)>
	{
		use LoadDriverError::*;
		
		match self
		{
			CouldNotAllocateMemoryForOurDriverName(cause) => Some(cause),
			
			CouldNotAllocateMemoryForUsbDetails(cause) => Some(cause),
			
			CapabilitiesIsNotHexadecimal(cause) => Some(cause),
			
			CapabilitiesBitFlagsAreUnknown(cause) => Some(cause),
			
			VendorIdentifierIsNotHexadecimal(cause) => Some(cause),
			
			ProductIdentifierIsNotHexadecimal(cause) => Some(cause),
			
			LoadLibrary(cause) => Some(cause),
			
			GetSymbol { cause, .. } => Some(cause),
			
			_ => None,
		}
	}
}
