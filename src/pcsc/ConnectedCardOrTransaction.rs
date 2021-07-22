// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/raphaelcohn/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/raphaelcohn/security-keys-rust/master/COPYRIGHT.


/// Unifies the methods available on a `ConnectedCard` and a `ConnectedCardTransaction`.
pub trait ConnectedCardOrTransaction: Sized
{
	/// Active protocol.
	fn active_protocol(&self) -> Option<Protocol>;
	
	/// High-level API; generally the most useful.
	#[inline(always)]
	fn status_or_disconnect_activity<CardStatusUser: for <'a> FnOnce(CardReaderName<'a>, InsertionsAndRemovalsCount, HashSet<CardStatus>, Protocol, AnswerToReset<'a>) -> R, R>(self, card_status_user: CardStatusUser) -> Result<(Self, R), ActivityError>
	{
		self.status_or_disconnect(card_status_user).map_err(ActivityError::CardStatus)
	}
	
	/// Mid-level API that ensures a card is properly disconnected.
	fn status_or_disconnect<CardStatusUser: for <'a> FnOnce(CardReaderName<'a>, InsertionsAndRemovalsCount, HashSet<CardStatus>, Protocol, AnswerToReset<'a>) -> R, R>(self, card_status_user: CardStatusUser) -> Result<(Self, R), WithDisconnectError<CardStatusError>>;
	
	/// Low-level API.
	fn status<CardStatusUser: for <'a> FnOnce(CardReaderName<'a>, InsertionsAndRemovalsCount, HashSet<CardStatus>, Protocol, AnswerToReset<'a>) -> R, R>(&self, card_status_user: CardStatusUser) -> Result<R, CardStatusError>;
}
