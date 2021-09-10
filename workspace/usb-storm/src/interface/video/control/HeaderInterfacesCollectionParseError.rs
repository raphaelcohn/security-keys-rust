// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// Parse error.
#[derive(Debug, Clone, PartialEq, Eq)]
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub enum HeaderInterfacesCollectionParseError
{
	#[allow(missing_docs)]
	ThereMustBeAtLeastOneInterfaceInTheCollection,
	
	#[allow(missing_docs)]
	NotEnoughBytesForAllInterfacesInTheCollection,
	
	#[allow(missing_docs)]
	TooManyInterfacesInTheCollection
	{
		bInCollection: u8
	},
	
	#[allow(missing_docs)]
	CouldNotAllocateInterfacesCollection(#[serde(with = "TryReserveErrorRemote")] TryReserveError),
	
	#[allow(missing_docs)]
	InterfaceNumberTooLarge
	{
		baInterfaceNr: u8,
	},
	
	#[allow(missing_docs)]
	DuplicateInterfaceNumber
	{
		interface_number: InterfaceNumber,
	},
}

impl Display for HeaderInterfacesCollectionParseError
{
	#[inline(always)]
	fn fmt(&self, f: &mut Formatter) -> fmt::Result
	{
		Debug::fmt(self, f)
	}
}

impl error::Error for HeaderInterfacesCollectionParseError
{
	#[inline(always)]
	fn source(&self) -> Option<&(dyn error::Error + 'static)>
	{
		use HeaderInterfacesCollectionParseError::*;
		
		match self
		{
			CouldNotAllocateInterfacesCollection(cause) => Some(cause),
			
			_ => None,
		}
	}
}
