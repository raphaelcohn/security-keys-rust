// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// Version.
#[derive(Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Version
{
	major: u8,

	minor: u4,

	sub_minor: u4,
}

impl Display for Version
{
	#[inline(always)]
	fn fmt(&self, f: &mut Formatter) -> fmt::Result
	{
		write!(f, "{}.{}.{}", self.major, self.minor, self.sub_minor)
	}
}

/// This is for a little-endian `u16`.
impl Version
{
	/// Major version.
	///
	/// Values between 0 and 100 inclusive.
	#[inline(always)]
	pub const fn major(&self) -> u8
	{
		self.major
	}
	
	/// Minor version.
	///
	/// Values between 0 and 9 inclusive.
	#[inline(always)]
	pub const fn minor(&self) -> u4
	{
		self.minor
	}
	
	/// Sub-minor version.
	///
	/// Values between 0 and 9 inclusive.
	#[inline(always)]
	pub const fn sub_minor(&self) -> u4
	{
		self.sub_minor
	}
	
	#[inline(always)]
	pub(crate) const fn is_3_0_or_greater(&self) -> bool
	{
		self.minor >= 3
	}
	
	/// An USB binary coded decimal field is structured as `0xJJMN`:-
	///
	/// * `JJ` is the major version.
	/// * `M` is the minor version.
	/// * `N` is the sub-minor version.
	#[inline(always)]
	pub(super) fn parse(binary_coded_decimal: u16) -> Result<Self, VersionParseError>
	{
		use VersionParseError::*;
		
		const Base10: u8 = 10;
		
		#[inline(always)]
		const fn extract_digit<const index: u16>(binary_coded_decimal: u16) -> u8
		{
			const DigitNibbleBits: u16 = 4;
			const DigitNibbleMask: u16 = (1 << DigitNibbleBits) - 1;
			
			let shift = DigitNibbleBits * index;
			
			((binary_coded_decimal >> shift) & DigitNibbleMask) as u8
		}
		
		#[inline(always)]
		fn parse_digit<E: FnOnce(u8) -> VersionParseError, const index: u16>(binary_coded_decimal: u16, error: E) -> Result<u4, VersionParseError>
		{
			let raw_digit = extract_digit::<index>(binary_coded_decimal);
			if likely!(raw_digit < Base10)
			{
				Ok(raw_digit)
			}
			else
			{
				Err(error(raw_digit))
			}
		}
		
		Ok
		(
			Self
			{
				major:
				{
					let major_left_hand_digit = parse_digit::<_, 3>(binary_coded_decimal, MajorLeftHandDigitOutOfRange)?;
					let major_right_hand_digit = parse_digit::<_, 2>(binary_coded_decimal, MajorRightHandDigitOutOfRange)?;
					(major_left_hand_digit * Base10) + major_right_hand_digit
				},
			
				minor: parse_digit::<_, 1>(binary_coded_decimal, MinorOutOfRange)?,
			
				sub_minor: parse_digit::<_, 0>(binary_coded_decimal, SubMinorOutOfRange)?,
			}
		)
	}
}
