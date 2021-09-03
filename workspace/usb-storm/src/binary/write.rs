// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


pub(super) fn write(matches: &CommandLineParser, writer: impl Write + 'static) -> Result<(), ProgramError>
{
	let devices = Devices::list(Context::default()?)?;
	let mut reusable_buffer = ReusableBuffer::new().map_err(ProgramError::CouldNotCreateBinaryObjectStoreBuffer)?;
	let devices = devices.parse(&mut reusable_buffer)?;

	let format = matches.format();
	which_serialize(format, devices, writer)?;
	Ok(())
}
