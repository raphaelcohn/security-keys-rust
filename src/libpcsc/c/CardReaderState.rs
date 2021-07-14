// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


#[derive(Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
pub(crate) enum CardReaderState<'answer_to_reset>
{
	Ignored,
	
	Unavailable,
	
	/// The reader name was not known on the system; this can only occur after entering the wait loop, otherwise an error (`SCARD_E_UNKNOWN_READER`) is immediately returned.
	Unknown,
	
	/// There is no card in the card reader.
	Empty,
	
	Present
	{
		exclusivity: PresentExclusivity,
		
		/// Also known as unresponsive.
		is_mute: bool,
		
		answer_to_reset: AnswerToReset<'answer_to_reset>,
	}
}
