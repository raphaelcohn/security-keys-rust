// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// Audio Video Device (AV) interface sub class.
#[derive(Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub enum AudioVideoInterfaceSubClass
{
	/// Audio/Video Device – AVControl Interface.
	///
	/// Should be `None` if recognized.
	Control(Option<NonZeroU8>),
	
	/// Audio/Video Device – AVData Video Streaming Interface.
	///
	/// Should be `None` if recognized.
	DataVideoStreamingInterface(Option<NonZeroU8>),
	
	/// Audio/Video Device – AVData Audio Streaming Interface.
	///
	/// Should be `None` if recognized.
	DataAudioStreamingInterface(Option<NonZeroU8>),

	/// Unrecognized.
	Unrecognized(UnrecognizedSubClass),
}
