// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// An output terminal entity.
pub trait OutputTerminalEntity: TerminalEntity
{
	#[allow(missing_docs)]
	fn output_terminal_type(&self) -> OutputTerminalType;
	
	#[allow(missing_docs)]
	fn associated_input_terminal(&self) -> Option<TerminalEntityIdentifier>;
	
	#[allow(missing_docs)]
	fn output_logical_audio_channel_cluster(&self) -> Option<UnitOrTerminalEntityIdentifier>;
}
