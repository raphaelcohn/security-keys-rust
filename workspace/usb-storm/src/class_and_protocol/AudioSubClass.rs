// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// Audio sub class.
#[derive(Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub enum AudioSubClass
{
	#[allow(missing_docs)]
	Control(AudioProtocol),
	
	#[allow(missing_docs)]
	Streaming(AudioProtocol),
	
	/// MIDI streaming.
	MidiStreaming(KnownOrUnrecognizedProtocol),

	#[allow(missing_docs)]
	Unrecognized(UnrecognizedSubClass),
}
