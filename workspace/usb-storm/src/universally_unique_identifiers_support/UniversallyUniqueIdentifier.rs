// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// An Universally-Unique identifier (UUID) or Globally Unique Identifier (GUID).
#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
pub struct UniversallyUniqueIdentifier
{
	rfc_41222_big_endian_bytes: [u8; UniversallyUniqueIdentifier::Length],
}

impl Default for UniversallyUniqueIdentifier
{
	#[inline(always)]
	fn default() -> Self
	{
		Self::Nil
	}
}

impl Debug for UniversallyUniqueIdentifier
{
	#[inline(always)]
	fn fmt(&self, f: &mut Formatter) -> fmt::Result
	{
		write!(f, "{}", self.to_rfc_4122_string())
	}
}

impl Display for UniversallyUniqueIdentifier
{
	#[inline(always)]
	fn fmt(&self, f: &mut Formatter) -> fmt::Result
	{
		Debug::fmt(self, f)
	}
}

impl Serialize for UniversallyUniqueIdentifier
{
	#[inline(always)]
	fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error>
	{
		if serializer.is_human_readable()
		{
			serializer.serialize_str(&self.to_hyphenated_lower_case_string())
		}
		else
		{
			serializer.serialize_bytes(&self.rfc_41222_big_endian_bytes)
		}
	}
}

impl<'de> Deserialize<'de> for UniversallyUniqueIdentifier
{
	#[inline(always)]
	fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error>
	{
		struct OurVisitor;
		
		impl<'vi> Visitor<'vi> for OurVisitor
		{
			type Value = UniversallyUniqueIdentifier;
			
			#[inline(always)]
			fn expecting(&self,	formatter: &mut Formatter<'_>) -> fmt::Result
			{
				write!(formatter, "an Universally Unique Identifier (UUID) string or bytes")
			}
			
			#[inline(always)]
			fn visit_str<E: de::Error>(self, value: &str) -> Result<Self::Value, E>
			{
				let length = value.len();
				if unlikely!(length != UniversallyUniqueIdentifier::Rfc4122StringLength)
				{
					return Err(E::invalid_length(length, &"a string of length 36"))
				}
				
				let pointer = value.as_ptr() as *const [u8; UniversallyUniqueIdentifier::Rfc4122StringLength];
				let string = unsafe { & * pointer };
				match catch_unwind(|| UniversallyUniqueIdentifier::parse_rfc_4122_string_or_panic(string))
				{
					Ok(universally_unique_identifier) => Ok(universally_unique_identifier),
					
					Err(panic) =>
					{
						let formatted_arguments = if let Some(string) = panic.downcast_ref::<String>()
						{
							format!("Universally Unique Identifier string parsing failed because of {}", string)
						}
						else
						{
							format!("Universally Unique Identifier string parsing failed")
						};
						Err(E::custom(formatted_arguments))
					},
				}
			}
			
			#[inline(always)]
			fn visit_bytes<E: de::Error>(self, value: &[u8]) -> Result<Self::Value, E>
			{
				let length = value.len();
				if unlikely!(length != UniversallyUniqueIdentifier::Length)
				{
					return Err(E::invalid_length(length, &"an array of bytes of length 16"))
				}
				
				let pointer = value.as_ptr() as *const [u8; UniversallyUniqueIdentifier::Length];
				Ok(UniversallyUniqueIdentifier::from_rfc_4122_bytes(unsafe { * pointer }))
			}
		}
		
		if deserializer.is_human_readable()
		{
			deserializer.deserialize_str(OurVisitor)
		}
		else
		{
			deserializer.deserialize_bytes(OurVisitor)
		}
	}
}

impl UniversallyUniqueIdentifier
{
	const UrnPrefix: &'static [u8; 9] = b"urn:uuid:";
	
	const UrnPrefixLength: usize = Self::UrnPrefix.len();
	
	const ExclusiveMaximumDecimal: u8 = 10;
	
	const DecimalOffset: u8 = b'0';
	
	const UpperCaseHexadecimalOffset: u8 = b'A' - Self::ExclusiveMaximumDecimal;
	
	const LowerCaseHexadecimalOffset: u8 = b'a' - Self::ExclusiveMaximumDecimal;
	
	/// Length.
	pub const Length: usize = size_of::<u128>();
	
	/// Length.
	pub const Rfc4122UrnStringLength: usize = Self::Rfc4122StringLength + Self::UrnPrefixLength;
	
	/// Length.
	pub const Rfc4122StringLength: usize = 36;
	
	/// Length.
	pub const MicrosoftStringLength: usize = 1 + Self::Rfc4122StringLength + 1;
	
	/// Length.
	pub const MicrosoftData4FieldLength: usize = 8;
	
	/// Nil.
	pub const Nil: Self = Self
	{
		rfc_41222_big_endian_bytes: [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
	};
	
	/// Currently, only versions 1 through 5 inclusive are defined (versions 0, 6 and 7) are undefined, although the 'Nil' value will have version 0.
	#[inline(always)]
	pub const fn version_number(self) -> u4
	{
		self.rfc_41222_big_endian_bytes[6] >> 4
	}
	
	/// Note that the `Nil` value will have variant `ApolloNetworkComputerSystemBackwardCompatibility`.
	#[inline(always)]
	pub const fn variant(self) -> Variant
	{
		use Variant::*;
		
		match self.rfc_41222_big_endian_bytes[8] >> 5
		{
			0b000 | 0b001 | 0b010 | 0b011 => ApolloNetworkComputerSystemBackwardCompatibility,
			
			0b100 | 0b101 => Rfc4122,
			
			0b110 => MicrosoftGloballyUniqueIdentifier,
			
			0b111 => ReservedForFutureUse,
			
			_ => unreachable!()
		}
	}
	
	/// RFC 4122 timestamp, in native-endian order.
	///
	/// For version 1, this is value in UTC as a count of 100 nanosecond intervals since 00:00:00.00, 15 October 1582 (the date of Gregorian reform to the Christian calendar).
	/// For versions 3 and 5, this is derived from a name.
	/// For version 4, this is a random value.
	#[inline(always)]
	pub const fn rfc_4122_time_stamp_without_version_number(self) -> u60
	{
		const VersionBitMask: u64 = 0b1111 << 60;
		
		self.native_endian_u64::<0>() | VersionBitMask
	}
	
	/// RFC 4122 clock sequence, in native-endian order.
	///
	/// For version 1, this is a monotonically increasing sequence.
	/// For versions 3 and 5, this is derived from a name.
	/// For version 4, this is a random value.
	///
	/// It includes the lowest bit of the variant, thus
	///
	/// * For `MicrosoftGloballyUniqueIdentifier`, it is a 13-bit number but with the 13th bit (zero-based) set to 0.
	/// * For `ReservedForFutureUse`, it is effectively a 13-bit number but with the 13th bit (zero-based) set to 1.
	#[inline(always)]
	pub const fn rfc_4122_clock_sequence_without_variant(self) -> u14
	{
		(((self.rfc_clock_seq_hi_and_reserved()  | 0b0011_1111) as u16) << 8) | (self.rfc_4122_clock_seq_low() as u16)
	}
	
	/// RFC 4122 `node` field, in *big-endian* order (unlike the other RFC 4122 fields below).
	///
	/// For version 1, this is an IEEE 802 MAC address.
	/// For version 3 and 5, this is derived from a name.
	/// For version 4, this is a random value.
	#[inline(always)]
	pub const fn rfc_4122_node(self) -> [u8; 6]
	{
		self.read_value::<[u8; 6], 10>()
	}
	
	/// RFC 4122 `time_low` field, in native-endian order.
	#[inline(always)]
	pub const fn rfc_4122_time_low(self) -> u32
	{
		self.native_endian_u32::<0>()
	}
	
	/// RFC 4122 `time_mid` field, in native-endian order.
	#[inline(always)]
	pub const fn rfc_4122_time_mid(self) -> u16
	{
		self.native_endian_u16::<2>()
	}
	
	/// RFC 4122 `time_hi_and_version` field, in native-endian order.
	#[inline(always)]
	pub const fn rfc_4122_time_hi_and_version(self) -> u16
	{
		self.native_endian_u16::<4>()
	}
	
	/// RFC 4122 `clock_seq_hi_res` field, in native-endian order.
	#[inline(always)]
	pub const fn rfc_clock_seq_hi_and_reserved(self) -> u8
	{
		self.native_endian_u8::<8>()
	}
	
	/// RFC 4122 `clock_seq_low` field, in native-endian order.
	#[inline(always)]
	pub const fn rfc_4122_clock_seq_low(self) -> u8
	{
		self.native_endian_u8::<9>()
	}
	
	/// From big-endian ordered bytes (also known as network byte order).
	///
	/// This binary format is used by RFC 4122.
	#[inline(always)]
	pub const fn from_rfc_4122_bytes(rfc_41222_big_endian_bytes: [u8; UniversallyUniqueIdentifier::Length]) -> Self
	{
		Self
		{
			rfc_41222_big_endian_bytes
		}
	}
	
	/// This is the byte order used by Microsoft GUIDs and for transmission over USB.
	///
	/// The first three fields are little-endian; the remaining data is big-endian.
	///
	/// This is sometimes (mistakenly in my view) called 'little-endian', eg by Python's `uuid::UUID.bytes_le`.
	#[inline(always)]
	pub const fn from_microsoft_mixed_endian_bytes(microsoft_mixed_endian_bytes: &[u8; UniversallyUniqueIdentifier::Length]) -> Self
	{
		Self
		{
			rfc_41222_big_endian_bytes:
			[
				microsoft_mixed_endian_bytes[3],
				microsoft_mixed_endian_bytes[2],
				microsoft_mixed_endian_bytes[1],
				microsoft_mixed_endian_bytes[0],
				
				microsoft_mixed_endian_bytes[5],
				microsoft_mixed_endian_bytes[4],
				
				microsoft_mixed_endian_bytes[7],
				microsoft_mixed_endian_bytes[6],
				
				microsoft_mixed_endian_bytes[8],
				microsoft_mixed_endian_bytes[9],
				microsoft_mixed_endian_bytes[10],
				microsoft_mixed_endian_bytes[11],
				microsoft_mixed_endian_bytes[12],
				microsoft_mixed_endian_bytes[13],
				microsoft_mixed_endian_bytes[14],
				microsoft_mixed_endian_bytes[15],
			],
		}
	}
	
	/// Into microsoft mixed endiab bytes.
	///
	/// This is the format used for transmission over USB.
	#[inline(always)]
	pub const fn as_big_endian_bytes(&self) -> &[u8; UniversallyUniqueIdentifier::Length]
	{
		&self.rfc_41222_big_endian_bytes
	}
	
	/// Into microsoft mixed endian bytes.
	///
	/// This is the format used for transmission over USB.
	#[inline(always)]
	pub const fn into_big_endian_bytes(self) -> [u8; UniversallyUniqueIdentifier::Length]
	{
		self.rfc_41222_big_endian_bytes
	}
	
	/// Into microsoft mixed endiab bytes.
	///
	/// This is the format used for transmission over USB.
	#[inline(always)]
	pub const fn into_microsoft_mixed_endian_bytes(self) -> [u8; UniversallyUniqueIdentifier::Length]
	{
		[
			self.rfc_41222_big_endian_bytes[3],
			self.rfc_41222_big_endian_bytes[2],
			self.rfc_41222_big_endian_bytes[1],
			self.rfc_41222_big_endian_bytes[0],
			
			self.rfc_41222_big_endian_bytes[5],
			self.rfc_41222_big_endian_bytes[4],
			
			self.rfc_41222_big_endian_bytes[7],
			self.rfc_41222_big_endian_bytes[6],
			
			self.rfc_41222_big_endian_bytes[8],
			self.rfc_41222_big_endian_bytes[9],
			self.rfc_41222_big_endian_bytes[10],
			self.rfc_41222_big_endian_bytes[11],
			self.rfc_41222_big_endian_bytes[12],
			self.rfc_41222_big_endian_bytes[13],
			self.rfc_41222_big_endian_bytes[14],
			self.rfc_41222_big_endian_bytes[15],
		]
	}
	
	/// From a Microsoft GUID struct.
	///
	/// From the fields of a `winapi::shared::guiddef::GUID` struct:-
	///
	/// ```rust
	/// UniversallyUniqueIdentifier::from_microsoft_guid_components(guid.Data1, guid.Data2, guide.Data3, guide.Data4)
	/// ```
	///
	/// Fields `Data1`, `Data2` and `Data3` are assumed to be native endian.
	/// Field `Data4` is assumed to always be big endian.
	#[inline(always)]
	pub const fn from_microsoft_guid_fields(Data1: u32, Data2: u16, Data3: u16, Data4: [u8; UniversallyUniqueIdentifier::MicrosoftData4FieldLength]) -> Self
	{
		Self
		{
			rfc_41222_big_endian_bytes:
			[
				Data1 as u8,
				(Data1 >> 8) as u8,
				(Data1 >> 16) as u8,
				(Data1 >> 24) as u8,
				
				Data2 as u8,
				(Data2 >> 8) as u8,
				
				Data3 as u8,
				(Data3 >> 8) as u8,
				
				Data4[0],
				Data4[1],
				Data4[2],
				Data4[3],
				Data4[4],
				Data4[5],
				Data4[6],
				Data4[7],
			],
		}
	}
	
	/// Fields `Data1`, `Data2` and `Data3` will be native endian.
	/// Field `Data4` will always be big endian.
	#[inline(always)]
	pub const fn as_microsoft_guid_fields(&self) -> (u32, u16, u16, [u8; UniversallyUniqueIdentifier::MicrosoftData4FieldLength])
	{
		let Data1 = self.native_endian_u32::<0>();
		let Data2 = self.native_endian_u16::<4>();
		let Data3 = self.native_endian_u16::<6>();
		let Data4 = self.read_value::<[u8; UniversallyUniqueIdentifier::MicrosoftData4FieldLength], 10>();
		
		(Data1, Data2, Data3, Data4)
	}
	
	/// Parse a hexadecimal case-insensitive string which is like `xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx` or panic; suitable for initializing constants.
	#[inline(always)]
	pub const fn parse_rfc_4122_string_or_panic(string: &[u8; UniversallyUniqueIdentifier::Rfc4122StringLength]) -> Self
	{
		Self
		{
			rfc_41222_big_endian_bytes: UniversallyUniqueIdentifierStringParser(string).parse(),
		}
	}

	/// Parse a hexadecimal case-insensitive string which is like `{xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx}` or panic; suitable for initializing constants.
	#[inline(always)]
	pub const fn parse_microsoft_string_or_panic(string: &[u8; UniversallyUniqueIdentifier::MicrosoftStringLength]) -> Self
	{
		Self
		{
			rfc_41222_big_endian_bytes: MicrosoftUniversallyUniqueIdentifierStringParser(string).parse(),
		}
	}
	
	/// Parse a hexadecimal case-insensitive string which is like `xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx` or panic; suitable for initializing constants.
	#[inline(always)]
	pub const fn parse_rfc_4122_urn_string_or_panic(string: &[u8; UniversallyUniqueIdentifier::Rfc4122UrnStringLength]) -> Self
	{
		#[inline(always)]
		const fn validate_urn_prefix_byte<const index: usize>(string: &[u8; UniversallyUniqueIdentifier::Rfc4122UrnStringLength])
		{
			if string[index] != UniversallyUniqueIdentifier::UrnPrefix[index]
			{
				panic!("Does not start with prefix")
			}
		}
		
		validate_urn_prefix_byte::<0>(string);
		validate_urn_prefix_byte::<1>(string);
		validate_urn_prefix_byte::<2>(string);
		validate_urn_prefix_byte::<3>(string);
		validate_urn_prefix_byte::<4>(string);
		validate_urn_prefix_byte::<5>(string);
		validate_urn_prefix_byte::<6>(string);
		validate_urn_prefix_byte::<7>(string);
		validate_urn_prefix_byte::<8>(string);
		
		let string = unsafe { & * (string.as_ptr().add(Self::UrnPrefixLength) as *const [u8; Self::Rfc4122StringLength]) };
		
		Self
		{
			rfc_41222_big_endian_bytes: UniversallyUniqueIdentifierStringParser(string).parse(),
		}
	}
	
	/// Format as a hexadecimal lower case string which is like `xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx`.
	///
	/// Identical to `to_hyphenated_lower_case_string()`.
	#[inline(always)]
	pub fn to_rfc_4122_string(&self) -> ArrayString<{ UniversallyUniqueIdentifier::Rfc4122StringLength }>
	{
		self.to_hyphenated_lower_case_string()
	}
	
	/// Format as a hexadecimal lower case string which is like `xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx`.
	#[inline(always)]
	pub fn to_hyphenated_lower_case_string(&self) -> ArrayString<{ UniversallyUniqueIdentifier::Rfc4122StringLength }>
	{
		self.to_hyphenated_string::<{ UniversallyUniqueIdentifier::LowerCaseHexadecimalOffset }>()
	}
	
	/// Format as a hexadecimal upper case string which is like `XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX`.
	#[inline(always)]
	pub fn to_hyphenated_upper_case_string(&self) -> ArrayString<{ UniversallyUniqueIdentifier::Rfc4122StringLength }>
	{
		self.to_hyphenated_string::<{ UniversallyUniqueIdentifier::UpperCaseHexadecimalOffset }>()
	}
	
	/// Format as a hexadecimal lower case string which is like `{xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx}`.
	///
	/// Identical to `to_braced_hyphenated_lower_case_string()`.
	#[inline(always)]
	pub fn to_microsoft_string(&self) -> ArrayString<{ UniversallyUniqueIdentifier::MicrosoftStringLength }>
	{
		self.to_braced_hyphenated_lower_case_string()
	}
	
	/// Format as a hexadecimal lower case string which is like `{xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx}`.
	#[inline(always)]
	pub fn to_braced_hyphenated_lower_case_string(&self) -> ArrayString<{ UniversallyUniqueIdentifier::MicrosoftStringLength }>
	{
		self.to_braced_hyphenated_string::<{ UniversallyUniqueIdentifier::LowerCaseHexadecimalOffset }>()
	}
	
	/// Format as a hexadecimal lower case string which is like `{XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX}`.
	#[inline(always)]
	pub fn to_braced_hyphenated_upper_case_string(&self) -> ArrayString<{ UniversallyUniqueIdentifier::MicrosoftStringLength }>
	{
		self.to_braced_hyphenated_string::<{ UniversallyUniqueIdentifier::UpperCaseHexadecimalOffset }>()
	}
	
	/// Format as a hexadecimal lower case string which is like `urn:uuid:xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx`.
	#[inline(always)]
	pub fn to_rfc_4122_urn_string(&self) -> ArrayString<{ UniversallyUniqueIdentifier::Rfc4122UrnStringLength }>
	{
		const CAP: usize = UniversallyUniqueIdentifier::Rfc4122UrnStringLength;
		let mut array_vec: ArrayVec<u8, CAP> = ArrayVec::new_const();
		
		unsafe
		{
			array_vec.as_mut_ptr().copy_from_nonoverlapping(Self::UrnPrefix.as_ptr(), Self::UrnPrefixLength);
			array_vec.set_len(Self::UrnPrefixLength);
		}
		
		self.to_hyphenated_string_inner::<{ UniversallyUniqueIdentifier::LowerCaseHexadecimalOffset }, CAP>(&mut array_vec);
		unsafe { transmute(array_vec) }
		
	}
	
	#[inline(always)]
	fn to_hyphenated_string<const hexadecimal_offset: u8>(&self) -> ArrayString<{ UniversallyUniqueIdentifier::Rfc4122StringLength }>
	{
		const CAP: usize = UniversallyUniqueIdentifier::Rfc4122StringLength;
		let mut array_vec: ArrayVec<u8, CAP> = ArrayVec::new_const();
		
		self.to_hyphenated_string_inner::<hexadecimal_offset, CAP>(&mut array_vec);
		
		unsafe { transmute(array_vec) }
	}
	
	#[inline(always)]
	fn to_braced_hyphenated_string<const hexadecimal_offset: u8>(&self) -> ArrayString<{ UniversallyUniqueIdentifier::MicrosoftStringLength }>
	{
		const CAP: usize = UniversallyUniqueIdentifier::MicrosoftStringLength;
		let mut array_vec: ArrayVec<u8, CAP> = ArrayVec::new_const();
		
		Self::array_vec_push_byte(&mut array_vec, b'{');
		self.to_hyphenated_string_inner::<hexadecimal_offset, CAP>(&mut array_vec);
		Self::array_vec_push_byte(&mut array_vec, b'}');
		
		unsafe { transmute(array_vec) }
	}
	
	#[inline(always)]
	fn to_hyphenated_string_inner<const hexadecimal_offset: u8, const CAP: usize>(&self, array_vec: &mut ArrayVec<u8, CAP>)
	{
		#[inline(always)]
		fn push_hyphen<const CAP: usize>(array_string: &mut ArrayVec<u8, CAP>)
		{
			unsafe { array_string.push_unchecked(b'-') }
		}
		
		self.byte_to_hexadecimal::<hexadecimal_offset, CAP, 0>(array_vec);
		self.byte_to_hexadecimal::<hexadecimal_offset, CAP, 1>(array_vec);
		self.byte_to_hexadecimal::<hexadecimal_offset, CAP, 2>(array_vec);
		self.byte_to_hexadecimal::<hexadecimal_offset, CAP, 3>(array_vec);
		
		push_hyphen::<CAP>(array_vec);
		
		self.byte_to_hexadecimal::<hexadecimal_offset, CAP, 4>(array_vec);
		self.byte_to_hexadecimal::<hexadecimal_offset, CAP, 5>(array_vec);
		
		push_hyphen::<CAP>(array_vec);
		
		self.byte_to_hexadecimal::<hexadecimal_offset, CAP, 6>(array_vec);
		self.byte_to_hexadecimal::<hexadecimal_offset, CAP, 7>(array_vec);
		
		push_hyphen::<CAP>(array_vec);
		
		self.byte_to_hexadecimal::<hexadecimal_offset, CAP, 8>(array_vec);
		self.byte_to_hexadecimal::<hexadecimal_offset, CAP, 9>(array_vec);
		
		push_hyphen(array_vec);
		
		self.byte_to_hexadecimal::<hexadecimal_offset, CAP, 10>(array_vec);
		self.byte_to_hexadecimal::<hexadecimal_offset, CAP, 11>(array_vec);
		self.byte_to_hexadecimal::<hexadecimal_offset, CAP, 12>(array_vec);
		self.byte_to_hexadecimal::<hexadecimal_offset, CAP, 13>(array_vec);
		self.byte_to_hexadecimal::<hexadecimal_offset, CAP, 14>(array_vec);
		self.byte_to_hexadecimal::<hexadecimal_offset, CAP, 15>(array_vec);
	}
	
	#[inline(always)]
	fn byte_to_hexadecimal<const hexadecimal_offset: u8, const CAP: usize, const byte_index: usize>(&self, array_vec: &mut ArrayVec<u8, CAP>)
	{
		#[inline(always)]
		fn push_nibble<const hexadecimal_offset: u8, const CAP: usize>(array_vec: &mut ArrayVec<u8, CAP>, nibble: u8)
		{
			UniversallyUniqueIdentifier::array_vec_push_byte::<CAP>(array_vec, nibble_to_hexadecimal_character::<hexadecimal_offset>(nibble))
		}
		
		#[inline(always)]
		const fn nibble_to_hexadecimal_character<const hexadecimal_offset: u8>(nibble: u8) -> u8
		{
			if nibble < UniversallyUniqueIdentifier::ExclusiveMaximumDecimal
			{
				UniversallyUniqueIdentifier::DecimalOffset + nibble
			}
			else
			{
				hexadecimal_offset + nibble
			}
		}
		
		let byte = self.rfc_41222_big_endian_bytes.get_unchecked_value_safe(byte_index);
		
		let upper_nibble = byte >> 4;
		push_nibble::<hexadecimal_offset, CAP>(array_vec, upper_nibble);
		
		let lower_nibble = byte & 0b1111;
		push_nibble::<hexadecimal_offset, CAP>(array_vec, lower_nibble);
	}
	
	#[inline(always)]
	fn array_vec_push_byte<const CAP: usize>(array_vec: &mut ArrayVec<u8, CAP>, byte: u8)
	{
		unsafe { array_vec.push_unchecked(byte) }
	}
	
	#[inline(always)]
	const fn native_endian_u8<const index: usize>(&self) -> u8
	{
		self.read_value::<u8, index>()
	}
	
	#[inline(always)]
	const fn native_endian_u16<const index: usize>(&self) -> u16
	{
		let value = self.read_value::<u16, index>();
		if cfg!(target_endian = "little")
		{
			value.swap_bytes()
		}
		else
		{
			value
		}
	}
	
	#[inline(always)]
	const fn native_endian_u32<const index: usize>(&self) -> u32
	{
		let value = self.read_value::<u32, index>();
		if cfg!(target_endian = "little")
		{
			value.swap_bytes()
		}
		else
		{
			value
		}
	}
	
	#[inline(always)]
	const fn native_endian_u64<const index: usize>(&self) -> u64
	{
		let value = self.read_value::<u64, index>();
		if cfg!(target_endian = "little")
		{
			value.swap_bytes()
		}
		else
		{
			value
		}
	}
	
	#[inline(always)]
	const fn read_value<T: Copy, const index: usize>(&self) -> T
	{
		let pointer = self.rfc_41222_big_endian_bytes.as_ptr() as *const T;
		unsafe { * pointer }
	}
}
