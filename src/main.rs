// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


use security_keys_rust::VecExt;
use security_keys_rust::pcsc::CardDisposition;
use security_keys_rust::pcsc::CardSharedAccessBackOff;
use security_keys_rust::pcsc::ConnectedCardOrTransaction;
use security_keys_rust::pcsc::Context;
use security_keys_rust::pcsc::Scope;
use security_keys_rust::pcsc::ShareModeAndPreferredProtocols;
use security_keys_rust::pcsc::attributes::AttributeIdentifier;
use security_keys_rust::pcsc::card_reader_name::CardReaderName;
use security_keys_rust::pcsc::errors::ActivityError;
use arrayvec::ArrayVec;


fn main() -> Result<(), ActivityError>
{
	let card_shared_access_back_off = CardSharedAccessBackOff::default();
	let reconnect_card_disposition = CardDisposition::Leave;
	let share_mode_and_preferred_protocols = ShareModeAndPreferredProtocols::SharedAnyProtocol;
	
	let context = Context::establish_activity(Scope::System)?;
	context.initial_card_reader_states_activity(|card_reader_name, insertions_and_removals_count, card_reader_state|
	{
		println!("Card Reader Name: {} with {} insertions or removals and state {:?}", card_reader_name.into_c_string().into_string().unwrap(), insertions_and_removals_count, card_reader_state);
	})?;
	let card_reader_name = CardReaderName::new(b"Yubico Yubikey 4 OTP U2F CCID" as &[u8])?;
	let connected_card = context.connect_card_activity(card_shared_access_back_off, reconnect_card_disposition, &card_reader_name, share_mode_and_preferred_protocols)?;
	
	println!("Active Protocol: {:?}", connected_card.active_protocol());
	
	let (connected_card, status) = connected_card.status_or_disconnect_activity(|card_reader_name, insertions_and_removals_count, card_status, active_protocol, answer_to_reset|
	{
		println!("Card Reader Name: {} with {} insertions or removals, state {:?}, active protocol {:?} and answer to reset {:?}", card_reader_name.into_c_string().into_string().unwrap(), insertions_and_removals_count, card_status, active_protocol, answer_to_reset);
	})?;
	println!("Status: {:?}", status);
	
	let transaction = connected_card.begin_transaction_or_disconnect_activity()?;
	
	let attribute_identifier = AttributeIdentifier::ChannelIdentifier;
	
	let (transaction, _attribute) = transaction.get_attribute_or_disconnect_activity(attribute_identifier, |attribute_value|
	{
		println!("Attribute value {:?}", attribute_value)
	})?;
	
	let attribute_value = ArrayVec::new_const();
	let (transaction, _exists) = transaction.set_attribute_or_disconnect_activity(attribute_identifier, &attribute_value)?;
	
	let send_buffer = Vec::new();
	let mut receive_buffer = Vec::new_buffer(Context::MaximumExtendedSendOrReceiveBufferSize).unwrap();
	let (transaction, _received) = transaction.transmit_application_protocol_data_unit_or_disconnect_activity(&send_buffer, &mut receive_buffer)?;
	
	transaction.end_and_disconnect_activity(CardDisposition::ColdReset)?;
	
	drop(context);
	
	Ok(())
}
