// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// Internet Printing Protocol (IPP) descriptor parse error.
#[derive(Debug, Clone, PartialEq, Eq)]
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub enum InternetPrintingProtocolInterfaceExtraDescriptorParseError
{
	#[allow(missing_docs)]
	DescriptorIsNeitherOfficialOrVendorSpecific(DescriptorType),
	
	/// This type of descriptor must be at least 9 bytes long (including `bLength`).
	BLengthIsLessThanMinimum,
	
	#[allow(missing_docs)]
	BLengthExceedsRemainingBytes,
	
	#[allow(missing_docs)]
	NoCapabilityDescriptors,
	
	#[allow(missing_docs)]
	UnrecognizedCapabilitiesType
	{
		bCapabilitiesType: u8,
	},
	
	#[allow(missing_docs)]
	UnrecognizedCapabilitiesLength
	{
		bCapabilitiesLength: u8,
	},
	
	#[allow(missing_docs)]
	ReservedAuthenticationInBasicCapabilities,
	
	#[allow(missing_docs)]
	InvalidVersionsSupportedString(GetLocalizedStringError),
	
	#[allow(missing_docs)]
	InvalidPrinterUniversallyUniqueIdentifierString(GetLocalizedStringError),
	
	#[allow(missing_docs)]
	VendorCapabilityDescriptorsCanNotBeAllocated(#[serde(with = "TryReserveErrorRemote")] TryReserveError),
	
	#[allow(missing_docs)]
	VendorCapabilityDescriptorHeaderTooShort
	{
		index: usize,
		
		length: usize,
	},
	
	#[allow(missing_docs)]
	VendorCapabilityDescriptorDoesNotUseVendorSpecificDescriptorType
	{
		index: usize,
		
		descriptor_type: DescriptorType,
	},
	
	#[allow(missing_docs)]
	VendorCapabilityDescriptorLengthTooShort
	{
		index: usize,
		
		length: usize,
		
		required_length: usize,
	},
	
	#[allow(missing_docs)]
	VendorCapabilityDescriptorBytesCanNotBeAllocated
	{
		#[serde(with = "TryReserveErrorRemote")] cause: TryReserveError,
		
		index: usize,
	},
}

impl Display for InternetPrintingProtocolInterfaceExtraDescriptorParseError
{
	#[inline(always)]
	fn fmt(&self, f: &mut Formatter) -> fmt::Result
	{
		Debug::fmt(self, f)
	}
}

impl error::Error for InternetPrintingProtocolInterfaceExtraDescriptorParseError
{
	#[inline(always)]
	fn source(&self) -> Option<&(dyn error::Error + 'static)>
	{
		use InternetPrintingProtocolInterfaceExtraDescriptorParseError::*;
		
		match self
		{
			InvalidVersionsSupportedString(cause) => Some(cause),
			
			InvalidPrinterUniversallyUniqueIdentifierString(cause) => Some(cause),
			
			VendorCapabilityDescriptorsCanNotBeAllocated(cause) => Some(cause),
			
			VendorCapabilityDescriptorBytesCanNotBeAllocated { cause, .. } => Some(cause),
			
			_ => None,
		}
	}
}
