// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// Hub Transaction Translator (TT) protocol
#[derive(Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub enum HubTransactionTranslatorProtocol
{
	/// Should only be present for low-speed or full-speed.
	No,
	
	#[allow(missing_docs)]
	Single,
	
	#[allow(missing_docs)]
	Multiple,

	#[allow(missing_docs)]
	Unrecognized
	{
		protocol_code: u8,
	}
}
