// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// An input terminal entity.
pub trait InputTerminalEntity: TerminalEntity
{
	#[allow(missing_docs)]
	type LACC: Debug + Clone + Ord + Eq + Hash;
	
	#[allow(missing_docs)]
	fn input_terminal_type(&self) -> InputTerminalType;
	
	#[allow(missing_docs)]
	fn associated_output_terminal(&self) -> Option<TerminalEntityIdentifier>;
	
	#[allow(missing_docs)]
	fn output_logical_audio_channel_cluster(&self) -> &Self::LACC;
}
