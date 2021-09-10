// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// Sources (terminal or unit entity identifiers).
#[derive(Debug, Clone, PartialEq, Eq, Ord, PartialOrd, Hash)]
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Sources(WrappedIndexSet<EntityIdentifier>);

impl Deref for Sources
{
	type Target = WrappedIndexSet<EntityIdentifier>;
	
	#[inline(always)]
	fn deref(&self) -> &Self::Target
	{
		&self.0
	}
}

impl Sources
{
	#[inline(always)]
	fn parse<const MinimumBLength: usize, const PinsIndex: usize>(bLengthUsize: usize, entity_body: &[u8]) -> Result<(Self, usize, usize), SourcesParseError>
	{
		use SourcesParseError::*;
		
		let bNrInPins = entity_body.u8(entity_index::<PinsIndex>());
		let bNrInPinsUsize = bNrInPins as usize;
		
		let minimum_b_length = MinimumBLength + bNrInPinsUsize;
		if unlikely!(bLengthUsize < minimum_b_length)
		{
			return Err(BLengthTooShortForNumberOfSources { bLength: bLengthUsize as u8, bNrInPins})
		}
		
		let first_source_index: usize = PinsIndex + 1;
		let mut sources = WrappedIndexSet::with_capacity(bNrInPinsUsize).map_err(CouldNotAllocateSources)?;
		for index in 0 .. bNrInPinsUsize
		{
			let entity_identifier = entity_body.optional_non_zero_u8(entity_index_non_constant(first_source_index + index)).ok_or(EmptySourceEntityIdentifier { index })?;
			let inserted = sources.insert(entity_identifier);
			if unlikely!(inserted == false)
			{
				return Err(DuplicateSource { index, entity_identifier } )
			}
		}
		Ok((Self(sources), first_source_index + bNrInPinsUsize, minimum_b_length))
	}
}
