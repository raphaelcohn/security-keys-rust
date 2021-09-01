// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// Audio format.
#[derive(Debug, Clone, Eq, PartialEq, PartialOrd, Ord, Hash)]
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub enum Version1AudioFormatDetail
{
	#[allow(missing_docs)]
	TypeI(Version1TypeIAudioFormatDetail),
	
	#[allow(missing_docs)]
	TypeII(Version1TypeIIAudioFormatDetail),
	
	#[allow(missing_docs)]
	TypeIII(Version1TypeIIIAudioFormatDetail),
}
