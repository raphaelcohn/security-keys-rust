// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// Parse error.
#[derive(Debug, Clone, PartialEq, Eq)]
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub enum SourcesParseError
{
	#[allow(missing_docs)]
	BLengthTooShortForNumberOfSources
	{
		bLength: u8,
	
		bNrInPins: u8,
	},
	
	#[allow(missing_docs)]
	CouldNotAllocateSources(#[serde(with = "TryReserveErrorRemote")] TryReserveError),
	
	#[allow(missing_docs)]
	EmptySourceEntityIdentifier
	{
		index: usize,
	},
	
	#[allow(missing_docs)]
	DuplicateSource
	{
		index: usize,
		
		entity_identifier: EntityIdentifier
	},
}

impl Display for SourcesParseError
{
	#[inline(always)]
	fn fmt(&self, f: &mut Formatter) -> fmt::Result
	{
		Debug::fmt(self, f)
	}
}

impl error::Error for SourcesParseError
{
	#[inline(always)]
	fn source(&self) -> Option<&(dyn error::Error + 'static)>
	{
		use SourcesParseError::*;
		
		match self
		{
			CouldNotAllocateSources(cause) => Some(cause),
			
			_ => None,
		}
	}
}
