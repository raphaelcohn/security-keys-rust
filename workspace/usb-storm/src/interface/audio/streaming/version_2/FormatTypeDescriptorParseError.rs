// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// Parse error.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Ord, PartialOrd, Hash)]
pub enum FormatTypeDescriptorParseError
{
	#[allow(missing_docs)]
	UnrecognizedFormatTypeCode
	{
		bFormatType: u8,
	},
	
	#[allow(missing_docs)]
	NoFormatTypeDescriptor,
	
	#[allow(missing_docs)]
	BLengthIsLessThanDescriptorHeaderLength,
	
	#[allow(missing_docs)]
	BLengthIsLessThanMinimum,
	
	#[allow(missing_docs)]
	BLengthExceedsRemainingBytes,
	
	#[allow(missing_docs)]
	UnrecognizedInterfaceDescriptorType
	{
		descriptor_type: DescriptorType,
	},
	
	#[allow(missing_docs)]
	UnrecognizedInterfaceDescriptorSubType
	{
		descriptor_sub_type: DescriptorSubType,
	},
	
	#[allow(missing_docs)]
	FormatTypeMismatch
	{
		general_format_type: u8,
		
		bFormatType: u8,
	},
	
	#[allow(missing_docs)]
	FormatTypeIBLengthLessThanMinimum,
	
	#[allow(missing_docs)]
	FormatTypeIIBLengthLessThanMinimum,
	
	#[allow(missing_docs)]
	FormatTypeIIIBLengthLessThanMinimum,
	
	#[allow(missing_docs)]
	FormatExtendedTypeIBLengthLessThanMinimum,
	
	#[allow(missing_docs)]
	FormatExtendedTypeIIBLengthLessThanMinimum,
	
	#[allow(missing_docs)]
	FormatTypeIIIExtendedBLengthLessThanMinimum,
	
	#[allow(missing_docs)]
	TypeISubslotSizeWrong
	{
		bSubslotSize: u8,
	},
	
	#[allow(missing_docs)]
	TypeIIISubslotSizeWrong
	{
		bSubslotSize: u8,
	},
}

impl Display for FormatTypeDescriptorParseError
{
	#[inline(always)]
	fn fmt(&self, f: &mut Formatter) -> fmt::Result
	{
		Debug::fmt(self, f)
	}
}

impl error::Error for FormatTypeDescriptorParseError
{
}
