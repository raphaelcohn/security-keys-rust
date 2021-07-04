// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// BER-TLV is defined in ISO 8825.
pub(crate) struct Tag
{
	class: TagClass,
	
	number: u64,
}

impl Tag
{
	pub(crate) const AID: Self = Self::from_one_byte_unchecked(0x6E);
	
	pub(crate) const Historical: Self = Self::from_two_bytes_unchecked(0x5F, 0x52);
	
	pub(crate) const ExtendedLengthInformation: Self = Self::from_two_bytes_unchecked(0x7F, 0x66);
	
	pub(crate) const ExtendedCapabilities: Self = Self::from_one_byte_unchecked(0xC0);
	
	pub(crate) const SigningKeyAlgorithm: Self = Self::from_one_byte_unchecked(0xC1);
	
	pub(crate) const DecryptionKeyAlgorithm: Self = Self::from_one_byte_unchecked(0xC2);
	
	pub(crate) const AuthenticationKeyAlgorithm: Self = Self::from_one_byte_unchecked(0xC3);
	
	pub(crate) const AttestationKeyAlgorithm: Self = Self::from_one_byte_unchecked(0xDA);
	
	pub(crate) const KeyFingerprints: Self = Self::from_one_byte_unchecked(0xC5);
	
	pub(crate) const PutSigningKeyFingerprint: Self = Self::from_one_byte_unchecked(0xC7);
	
	pub(crate) const PutDecryptionKeyFingerprint: Self = Self::from_one_byte_unchecked(0xC8);
	
	pub(crate) const PutAuthenticationKeyFingerprint: Self = Self::from_one_byte_unchecked(0xC9);
	
	pub(crate) const PutAttestationKeyFingerprint: Self = Self::from_one_byte_unchecked(0xDB);
	
	pub(crate) const PutSigningKeyTimestamp: Self = Self::from_one_byte_unchecked(0xCE);
	
	pub(crate) const PutDecryptionKeyTimestamp: Self = Self::from_one_byte_unchecked(0xCF);
	
	pub(crate) const PutAuthenticationKeyTimestamp: Self = Self::from_one_byte_unchecked(0xD0);
	
	pub(crate) const PutAttestationKeyTimestamp: Self = Self::from_one_byte_unchecked(0xDD);
	
	#[inline(always)]
	const fn from_one_byte_unchecked(leading_tag_byte: u8) -> Self
	{
		Self
		{
			class: TagClass::parse(leading_tag_byte),
			
			number: Self::unextended_number(leading_tag_byte),
		}
	}
	
	#[inline(always)]
	const fn from_two_bytes_unchecked(leading_tag_byte: u8, subsequent_tag_byte: u8) -> Self
	{
		Self
		{
			class: TagClass::parse(leading_tag_byte),
		
			number: (Self::unextended_number(leading_tag_byte) << Self::BitsPerSubsequentByte) | (subsequent_tag_byte as u64),
		}
	}
	
	#[inline(always)]
	const fn unextended_number(leading_tag_byte: u8) -> u64
	{
		Self::initial_tag_number(Self::bottom_5_bits(leading_tag_byte))
	}
	
	const ExtendedMask: u8 = 0b1_1111;
	
	#[inline(always)]
	const fn initial_tag_number(bottom_5_bits: u8) -> u64
	{
		bottom_5_bits as u64
	}
	
	#[inline(always)]
	const fn bottom_5_bits(leading_tag_byte: u8) -> u8
	{
		leading_tag_byte & Self::ExtendedMask
	}
	
	/// [ISO 7816-4 Annex D, Section D.2 Tag field](https://cardwerk.com/iso7816-4-annex-d-use-of-basic-encoding-rules-asn-1/)
	fn parse<'a>(input: &mut Input<'a>, leading_tag_byte: u8) -> Result<(Self, TagType), TagParseError>
	{
		let class = TagClass::parse(leading_tag_byte);
		let tag_type = TagType::parse(leading_tag_byte);
		
		let bottom_5_bits = Self::bottom_5_bits(leading_tag_byte);
		let initial_tag_number = Self::initial_tag_number(bottom_5_bits);
		let is_extended = bottom_5_bits == Self::ExtendedMask;
		let number = if is_extended
		{
			Self::parse_multi_byte_tag_number(input, initial_tag_number)?
		}
		else
		{
			initial_tag_number
		};
		
		Ok
		(
			(
				Self
				{
					class,
					
					number
				},
				
				tag_type,
			)
		)
	}
	
	const BitsPerSubsequentByte: u32 = 7;
	
	#[inline(always)]
	fn parse_multi_byte_tag_number(input: &mut Input, mut tag_number: u64) -> Result<u64, TagParseError>
	{
		use self::TagParseError::*;
		
		const LowerSevenBits: u8 = 0b0111_1111;
		const TopBit: u8 = 0b1000_0000;
		
		#[inline(always)]
		fn append_bits_to_tag_number(tag_number: u64, subsequent_byte_index: u8, subsequent_byte: u8) -> Result<u64, TagParseError>
		{
			Ok(tag_number.checked_shl(Tag::BitsPerSubsequentByte).ok_or(ShiftedTooFar { subsequent_byte_index })? | ((subsequent_byte & LowerSevenBits) as u64))
		}
		
		#[inline(always)]
		fn next_byte(input: &mut Input, subsequent_byte_index: u8) -> Result<u8, TagParseError>
		{
			input.take_error(|| OutOfDataForSubsequentByte { subsequent_byte_index })
		}
		
		let mut subsequent_byte_index = 0;
		let mut subsequent_byte =
		{
			let first_subsequent_byte = next_byte(input, subsequent_byte_index)?;
			if first_subsequent_byte & LowerSevenBits == 0
			{
				return Err(FirstSubsequentByteHasLower7BitsAllZero)
			}
			first_subsequent_byte
		};
		tag_number = append_bits_to_tag_number(tag_number, subsequent_byte_index, subsequent_byte)?;
		
		loop
		{
			let is_last_byte = (subsequent_byte & TopBit) == 0;
			if is_last_byte
			{
				break
			}
			subsequent_byte_index += 1;
			subsequent_byte = next_byte(input, subsequent_byte_index)?;
			tag_number = append_bits_to_tag_number(tag_number, subsequent_byte_index, subsequent_byte)?;
		}
		
		Ok(tag_number)
	}
}
