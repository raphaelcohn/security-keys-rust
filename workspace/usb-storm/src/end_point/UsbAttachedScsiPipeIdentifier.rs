// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// USB Attached SCSI (UAS) Protocol (UASP) pipe.
///
/// For a normal implementation, there should be 4 endpoints, with one of each of Command, Status, DataIn and DataOut.
#[derive(Debug, Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub enum UsbAttachedScsiPipeIdentifier
{
	#[allow(missing_docs)]
	Reserved(u8),

	#[allow(missing_docs)]
	Command,
	
	#[allow(missing_docs)]
	Status,
	
	#[allow(missing_docs)]
	DataIn,
	
	#[allow(missing_docs)]
	DataOut,
	
	#[allow(missing_docs)]
	VendorSpecific(u8),
}

impl UsbAttachedScsiPipeIdentifier
{
	#[inline(always)]
	fn parse(remaining_bytes: &[u8], bLength: u8) -> Result<Option<DeadOrAlive<(EndPointExtraDescriptor, usize)>>, UsbAttachedScsiPipeParseError>
	{
		use UsbAttachedScsiPipeParseError::*;
		
		const BLength: u8 = 4;
		let (descriptor_body, descriptor_body_length) = verify_remaining_bytes::<_, BLength>(remaining_bytes, bLength, BLengthIsLessThanMinimum, BLengthExceedsRemainingBytes)?;
		
		use UsbAttachedScsiPipeIdentifier::*;
		let pipe = match descriptor_body.u8(0)
		{
			0 => Reserved(0),
			
			1 => Command,
			
			2 => Status,
			
			3 => DataIn,
			
			4 => DataOut,
			
			value @ 5 ..= 0xDF => Reserved(value),
			
			value @ 0xE0 ..= 0xEF => VendorSpecific(value),
			
			value @ 0xF0 ..= 0xFF => Reserved(value),
		};
		
		//let _reserved_and_is_currently_zero =  descriptor_body.u8(1);
		
		Ok(Some(Alive((EndPointExtraDescriptor::UsbAttachedScsiPipe(pipe), descriptor_body_length))))
	}
}
