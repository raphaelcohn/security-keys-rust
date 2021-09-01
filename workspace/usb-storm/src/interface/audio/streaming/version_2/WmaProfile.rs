// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// WMA profile.
#[derive(Debug, Copy, Clone, Eq, PartialEq, PartialOrd, Ord, Hash)]
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
#[bitflags]
#[repr(u16)]
pub enum WmaProfile
{
	#[allow(missing_docs)]
	ProfileL1 = 1 << 0,
	
	#[allow(missing_docs)]
	ProfileL2 = 1 << 1,
	
	#[allow(missing_docs)]
	ProfileL3 = 1 << 2,
	
	#[allow(missing_docs)]
	ProfileOtherL = 1 << 3,
	
	#[allow(missing_docs)]
	ProfileSpeechS1 = 1 << 4,
	
	#[allow(missing_docs)]
	ProfileSpeechS2 = 1 << 5,
	
	#[allow(missing_docs)]
	ProProfileSpeechM1 = 1 << 6,
	
	#[allow(missing_docs)]
	ProProfileSpeechM2 = 1 << 7,
	
	#[allow(missing_docs)]
	ProProfileSpeechM3 = 1 << 8,
	
	#[allow(missing_docs)]
	ProProfileSpeechOtherM = 1 << 9,
}
