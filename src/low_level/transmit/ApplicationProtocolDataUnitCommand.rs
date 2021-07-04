// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


#[derive(Debug, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
pub(crate) struct ApplicationProtocolDataUnitCommand<'data>
{
	/// `CLA`.
	class: u8,

	/// `INS`.
	instruction: u8,

	/// `P1` and `P2`.
	parameters: [u8; 2],

	data: Cow<'data, [u8]>,
}

impl<'data> ApplicationProtocolDataUnitCommand<'data>
{
	const LastChunkClass: u8 = 0x00;
	
	const NotLastChunkClass: u8 = 0x10;
	
	const ChangePinParameter1: u8 = 0x02;
	
	const PinPW1Parameter2: u8 = 0x81;
	
	const PinPW3Parameter2: u8 = 0x83;
	
	#[inline(always)]
	pub(super) fn number_of_chunks(&self, chunk_size: NonZeroU16) -> NonZeroUsize
	{
		debug_assert_eq!(self.class, Self::LastChunkClass);
		
		let data_length = self.data_length();
		let is_empty = data_length == 0;
		let chunk_size = if unlikely!(is_empty)
		{
			1
		}
		else
		{
			let chunk_size = chunk_size.get() as usize;
			(data_length + chunk_size - 1) / chunk_size
		};
		unsafe { NonZeroUsize::new_unchecked(chunk_size) }
	}
	
	#[inline(always)]
	fn data_length(&self) -> usize
	{
		self.data.len()
	}
	
	#[inline(always)]
	pub(super) fn into_chunk(&'data self, chunk_size: NonZeroU16, chunk_index: usize, is_final_chunk: bool) -> Self
	{
		debug_assert_eq!(self.class, Self::LastChunkClass);
		
		let chunk_size = chunk_size.get() as usize;
		let chunk_inclusive_start_index = chunk_size * chunk_index;
		let data = if unlikely!(is_final_chunk)
		{
			&self.data[chunk_inclusive_start_index .. ]
		}
		else
		{
			let chunk_exclusive_end_index = chunk_inclusive_start_index + chunk_size;
			&self.data[chunk_inclusive_start_index .. chunk_exclusive_end_index]
		};
		
		Self
		{
			class: if is_final_chunk
			{
				Self::LastChunkClass
			}
			else
			{
				Self::NotLastChunkClass
			},
		
			instruction: self.instruction,
		
			parameters: self.parameters,
		
			data: Cow::Borrowed(data),
		}
	}
	
	/// Pin called `PW1`.
	#[inline(always)]
	pub(super) fn verify_pin_user_81(user_pin: impl Into<Cow<'data, [u8]>>) -> Self
	{
		Self::verify_pin(Self::PinPW1Parameter2, user_pin)
	}
	
	/// Pin called `PW1`.
	#[inline(always)]
	pub(super) fn verify_pin_user_82(user_pin: impl Into<Cow<'data, [u8]>>) -> Self
	{
		Self::verify_pin(0x82, user_pin)
	}
	
	/// Pin called `PW3`.
	#[inline(always)]
	pub(super) fn verify_pin_admin(admin_pin: impl Into<Cow<'data, [u8]>>) -> Self
	{
		Self::verify_pin(Self::PinPW3Parameter2, admin_pin)
	}
	
	#[inline(always)]
	fn verify_pin(parameter2: u8, pin: impl Into<Cow<'data, [u8]>>) -> Self
	{
		Self::new(0x20, 0x00, parameter2, pin)
	}
	
	/// Pin called `PW1`.
	#[inline(always)]
	pub(super) fn change_pin_user_81(user_pin: impl Into<Cow<'data, [u8]>>) -> Self
	{
		Self::new(0x2C, Self::ChangePinParameter1,Self::PinPW1Parameter2, user_pin)
	}
	
	/// Pin called `PW3`.
	#[inline(always)]
	pub(super) fn change_pin_admin(old_admin_pin: impl AsRef<[u8]>, new_admin_pin: impl AsRef<[u8]>) -> Result<Self, TryReserveError>
	{
		let old_admin_pin = old_admin_pin.as_ref();
		let new_admin_pin = new_admin_pin.as_ref();
		
		let mut both_pins = Vec::new_with_capacity(old_admin_pin.len() + new_admin_pin.len())?;
		both_pins.extend_from_slice(old_admin_pin);
		both_pins.extend_from_slice(new_admin_pin);
		
		Ok(Self::new(0x24, Self::ChangePinParameter1, Self::PinPW3Parameter2, both_pins))
	}
	
	/// An ISO name is formatted `Surname>>GivenName`.
	#[inline(always)]
	pub(super) fn put_data_object_name(iso_name: impl Into<Cow<'data, [u8]>>) -> Self
	{
		Self::new_put_data_object_0x00(0x5B, iso_name)
	}
	
	/// A language is usually a lower-case 2 character ISO code, eg `en`.
	#[inline(always)]
	pub(super) fn put_data_object_language(iso_language_code: impl Into<Cow<'data, [u8]>>) -> Self
	{
		Self::new_put_data_object_0x5F(0x2D, iso_language_code)
	}
	
	#[inline(always)]
	pub(super) fn put_data_object_sex(sex: Sex) -> Self
	{
		let cow: Cow<'static, [u8]> = sex.into();
		Self::new_put_data_object_0x5F(0x35, cow)
	}
	
	#[inline(always)]
	pub(super) fn put_data_object_uniform_resource_locator(uniform_resource_locator: impl Into<Cow<'data, [u8]>>) -> Self
	{
		Self::new_put_data_object_0x5F(0x50, uniform_resource_locator)
	}
	
	#[inline(always)]
	fn new_put_data_object_0x00(parameter2: u8, data: impl Into<Cow<'data, [u8]>>) -> Self
	{
		Self::new_put_data_object(0x00, parameter2, data)
	}
	
	#[inline(always)]
	fn new_put_data_object_0x5F(parameter2: u8, data: impl Into<Cow<'data, [u8]>>) -> Self
	{
		Self::new_put_data_object(0x5F, parameter2, data)
	}
	
	#[inline(always)]
	fn new_put_data_object(parameter1: u8, parameter2: u8, data: impl Into<Cow<'data, [u8]>>) -> Self
	{
		Self::new(0xDA, parameter1, parameter2, data)
	}
	
	#[inline(always)]
	pub(super) fn new(instruction: u8, parameter1: u8, parameter2: u8, data: impl Into<Cow<'data, [u8]>>) -> Self
	{
		let data = data.into();
		debug_assert!(data.len() <= (u16::MAX) as usize);
		
		Self
		{
			class: Self::LastChunkClass,
			
			instruction,
			
			parameters: [parameter1, parameter2],
			
			data,
		}
	}
	
	#[inline(always)]
	pub(super) fn into_owned(self) -> ApplicationProtocolDataUnitCommand<'static>
	{
		ApplicationProtocolDataUnitCommand
		{
			class: self.class,
			
			instruction: self.instruction,
			
			parameters: self.parameters,
			
			data: Cow::Owned(self.data.into_owned())
		}
	}
	
	/// See OpenPGP smart card specification, chapter 7, page 47.
	/// See also <https://en.wikipedia.org/wiki/Smart_card_application_protocol_data_unit>
	pub(super) fn serialize<'send_buffer>(&self, response_length_encoding: ResponseLengthEncoding, buffers: &'send_buffer mut SendBuffer) -> &'send_buffer mut Vec<u8>
	{
		let buffer = buffers.reserve_send();
		self.encode_header(buffer);
		self.encode_variable_length_called_l_c(buffer, response_length_encoding);
		self.store_command_data(buffer);
		self.encode_variable_response_length_called_l_e(buffer, response_length_encoding);
		buffer
	}
	
	#[inline(always)]
	fn encode_header(&self, buffer: &mut Vec<u8>)
	{
		buffer.push(self.class);
		buffer.push(self.instruction);
		buffer.extend_from_slice(&self.parameters);
	}
	
	/// See ISO 7814-4 Section 5 (Basic Organization), Section 5.3.2 Decoding conventions for command bodies.
	/// eg <https://cardwerk.com/smart-card-standard-iso7816-4-section-5-basic-organizations> (previous version).
	/// Current Version is ISO/IEC 7816-4:2020.
	#[inline(always)]
	fn encode_variable_length_called_l_c(&self, buffer: &mut Vec<u8>, response_length_encoding: ResponseLengthEncoding)
	{
		let data_length = self.data_length();
		let is_empty = data_length == 0;
		
		// Encode data length bytes, which is a variable-length encoding.
		// The first byte dictates the encoding:-
		// 1 - 255: 'Short'
		// 0: 'Long'.
		{
			const RequiresLongEncoding: usize = u8::MAX as usize;
			if data_length > RequiresLongEncoding || response_length_encoding == ResponseLengthEncoding::Long
			{
				let data_length = data_length as u16;
				buffer.push(0x00);
				buffer.push((data_length >> 8) as u8);
				buffer.push((data_length & 0xFF) as u8);
			}
			else if is_empty
			{
			}
			else
			{
				buffer.push(data_length as u8);
			}
		}
	}
	
	#[inline(always)]
	fn store_command_data(&self, buffer: &mut Vec<u8>)
	{
		buffer.extend_from_slice(&self.data);
	}
	
	#[inline(always)]
	fn encode_variable_response_length_called_l_e(&self, buffer: &mut Vec<u8>, response_length_encoding: ResponseLengthEncoding)
	{
		match response_length_encoding
		{
			// No bytes denotes 0.
			ResponseLengthEncoding::None => (),
			
			// One zero byte denotes 256.
			ResponseLengthEncoding::Short => buffer.push(0x00),
			
			ResponseLengthEncoding::Long => if self.data.is_empty()
			{
				// Three zero bytes denotes 65,536 but that Lc was not present in the data length encoding.
				buffer.extend_from_slice(&[0x00, 0x00, 0x00])
			}
			else
			{
				// Two zero bytes denotes 65,536.
				buffer.extend_from_slice(&[0x00, 0x00])
			}
		}
	}
}

impl ApplicationProtocolDataUnitCommand<'static>
{
	pub(crate) const SelectApplicationOpenPgp: Self =
	{
		static Data: &'static [u8] = &[ApplicationIdentifier::RegisteredApplicationProviderIdentifier[0], ApplicationIdentifier::RegisteredApplicationProviderIdentifier[1], ApplicationIdentifier::RegisteredApplicationProviderIdentifier[2], ApplicationIdentifier::RegisteredApplicationProviderIdentifier[3], ApplicationIdentifier::RegisteredApplicationProviderIdentifier[4], ApplicationIdentifier::OpenPgpProprietaryApplicationIdentifierExtension];
		
		Self
		{
			class: Self::LastChunkClass,
			
			instruction: 0xA4,
			
			parameters: [0x04, 0x00],
			
			data: Cow::Borrowed(Data)
		}
	};
	
	pub(crate) const GetDataObjectApplicationRelatedData: Self = Self::new_get_data_object_0x00(0x6E);
	
	pub(super) const GetDataObjectCardholderRelatedData: Self = Self::new_get_data_object_0x00(0x65);
	
	pub(super) const GetDataObjectSecuritySupportTemplate: Self = Self::new_get_data_object_0x00(0x7A);
	
	pub(super) const GetDataObjectListOfSupportedAlgorithmAttributes: Self = Self::new_get_data_object_0x00(0xFA);
	
	pub(super) const GetDataObjectUniformResourceLocator: Self = Self::new_get_data_object(0x5F, 0x50);
	
	pub(super) const Decryption: Self = Self::new_cryptographic_operation(0x80, 0x86);
	
	pub(super) const Signature: Self = Self::new_cryptographic_operation(0x9E, 0x9A);
	
	pub(super) const GetResponse: Self = Self::new_empty(0xC0, 0x00, 0x00);
	
	pub(super) const TerminateDF: Self = Self::new_empty(0xE6, 0x00, 0x00);
	
	pub(super) const ActivateFile: Self = Self::new_empty(0x44, 0x00, 0x00);
	
	#[inline(always)]
	const fn new_get_data_object_0x00(parameter2: u8) -> Self
	{
		Self::new_get_data_object(0x00, parameter2)
	}
	
	#[inline(always)]
	const fn new_get_data_object(parameter1: u8, parameter2: u8) -> Self
	{
		Self::new_empty(0xCA, parameter1, parameter2)
	}
	
	#[inline(always)]
	const fn new_cryptographic_operation(parameter1: u8, parameter2: u8) -> Self
	{
		Self::new_empty(0x2A, parameter1, parameter2)
	}
	
	#[inline(always)]
	const fn new_empty(instruction: u8, parameter1: u8, parameter2: u8) -> Self
	{
		const Empty: &'static [u8] = b"";
		
		Self
		{
			class: Self::LastChunkClass,
			
			instruction,
			
			parameters: [parameter1, parameter2],
			
			data: Cow::Borrowed(Empty),
		}
	}
}
