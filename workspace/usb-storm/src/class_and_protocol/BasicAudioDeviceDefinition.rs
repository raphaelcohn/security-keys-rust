// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// Basic audio device definition.
#[derive(Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub enum BasicAudioDeviceDefinition
{
	#[allow(missing_docs)]
	GenericInputOutput,
	
	#[allow(missing_docs)]
	Headphone,
	
	#[allow(missing_docs)]
	Speaker,
	
	#[allow(missing_docs)]
	Microphone,
	
	#[allow(missing_docs)]
	Headset,
	
	#[allow(missing_docs)]
	HeadsetAdapater,
	
	#[allow(missing_docs)]
	Speakerphone,
	
	#[allow(missing_docs)]
	UnrecognizedBasicAudioDeviceDefinition
	{
		sub_class_code: u8,
	}
}
