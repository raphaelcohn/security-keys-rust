// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/raphaelcohn/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/raphaelcohn/security-keys-rust/master/COPYRIGHT.


pub(super) struct SmartCardConnection<CardOrTransaction: CardOrTransactionExt>
{
	card: CardOrTransaction,

	send_buffer: SendBuffer,

	receive_buffers: ReceiveBuffers,

	response: Response,
}

impl<CardOrTransaction: CardOrTransactionExt> SmartCardConnection<CardOrTransaction>
{
	#[inline(always)]
	pub(super) fn select_application_open_pgp(&mut self) -> Result<(), CardError>
	{
		self.card.send_command(ApplicationProtocolDataUnitCommand::SelectApplicationOpenPgp, ResponseLengthEncoding::Short, &mut self.send_buffer, &mut self.receive_buffers, &mut self.response, CommandChaining::Unsupported)
	}
	
	pub(super) fn get_application_open_pgp_data(&mut self) -> Result<ConstructedValues, GetApplicationOpenPgpDataError>
	{
		use self::GetApplicationOpenPgpDataError::*;
		
		self.card.send_command(ApplicationProtocolDataUnitCommand::GetDataObjectApplicationRelatedData, ResponseLengthEncoding::Short, &mut self.send_buffer, &mut self.receive_buffers, &mut self.response, CommandChaining::Unsupported);
		
		let constructed_values = ConstructedValues::parse_borrowed(self.response.deref())?;
		
		let application_identifier = Self::extract_object(&constructed_values, Tag::AID, MissingApplicationIdentifier, ApplicationIdentifier::parse)?;
		
		let historical = constructed_values.find_first_recursively_depth_first(Tag::Historical);
		let extended_length_information = constructed_values.find_first_recursively_depth_first(Tag::ExtendedLengthInformation);
		let extended_capabilities = constructed_values.find_first_recursively_depth_first(Tag::ExtendedCapabilities);
		let signing_key_algorithm = constructed_values.find_first_recursively_depth_first(Tag::SigningKeyAlgorithm);
		let decryption_key_algorithm = constructed_values.find_first_recursively_depth_first(Tag::DecryptionKeyAlgorithm);
		let authentication_key_algorithm = constructed_values.find_first_recursively_depth_first(Tag::AuthenticationKeyAlgorithm);
		let attestation_key_algorithm = constructed_values.find_first_recursively_depth_first(Tag::AttestationKeyAlgorithm);
		let key_fingerpints = constructed_values.find_first_recursively_depth_first(Tag::KeyFingerprints);
	}
	
	#[inline(always)]
	fn extract_object<Object, E: From<ParseE>, ParseE, Parser: FnOnce(&Values) -> Result<Object, ParseE>>(constructed_values: &ConstructedValues, tag: Tag, missing_error: E, parser: Parser) -> Result<Object, E>
	{
		match constructed_values.find_first_recursively_depth_first(tag)
		{
			None => Err(GetApplicationOpenPgpDataError::MissingApplicationIdentifier),
			
			Some(values) => parser(values).map_err(E::from),
		}
	}
}
