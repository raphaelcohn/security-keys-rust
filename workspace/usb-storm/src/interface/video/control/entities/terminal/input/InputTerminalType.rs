// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// Input terminal type.
#[derive(Debug, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub enum InputTerminalType
{
	#[allow(missing_docs)]
	Input(InputSpecificTerminalType),
	
	#[allow(missing_docs)]
	Common(CommonTerminalType),
}

impl InputTerminalType
{
	#[inline(always)]
	fn parse(bLengthUsize: usize, entity_body: &[u8], specification_version: Version) -> Result<Self, InputTerminalEntityParseError>
	{
		use InputTerminalEntityParseError::*;
		use InputTerminalType::*;
		
		match entity_body.u16(entity_index::<4>())
		{
			0x0100 => Self::usb(entity_body, UsbTerminalType::VendorSpecific, UsbTerminalTypeDiscriminants::VendorSpecific),
			0x0101 => Self::usb(entity_body, UsbTerminalType::Streaming, UsbTerminalTypeDiscriminants::Streaming),
			
			0x0200 => Ok(Input(InputSpecificTerminalType::VendorSpecific(Self::data(entity_body, CanNotAllocateMemoryForInputVendorSpecificTerminalType)?))),
			0x0201 => Ok(Input(InputSpecificTerminalType::parse_camera(bLengthUsize, entity_body, specification_version)?)),
			0x0202 => Ok(Input(InputSpecificTerminalType::parse_media_transport(bLengthUsize, entity_body)?)),
			
			0x0300 => Self::output_error(OutputSpecificTerminalTypeDiscriminants::VendorSpecific),
			0x0301 => Self::output_error(OutputSpecificTerminalTypeDiscriminants::Display),
			0x0302 => Self::output_error(OutputSpecificTerminalTypeDiscriminants::MediaTransport),
			
			0x0400 => Self::external(entity_body, ExternalTerminalType::VendorSpecific, ExternalTerminalTypeDiscriminants::VendorSpecific),
			0x0401 => Self::external(entity_body, ExternalTerminalType::CompositeConnector, ExternalTerminalTypeDiscriminants::CompositeConnector),
			0x0402 => Self::external(entity_body, ExternalTerminalType::SVideoConnector, ExternalTerminalTypeDiscriminants::SVideoConnector),
			0x0403 => Self::external(entity_body, ExternalTerminalType::ComponentConnector, ExternalTerminalTypeDiscriminants::ComponentConnector),
			
			wTerminalType @ _ => Ok(Common(CommonTerminalType::Unknown { wTerminalType, data: Self::data(entity_body, |cause| CanNotAllocateMemoryForUnknownTerminalType { wTerminalType, cause })? })),
		}
	}
	
	#[inline(always)]
	fn usb(entity_body: &[u8], usb_terminal_type: impl FnOnce(Vec<u8>) -> UsbTerminalType, usb_format_type: UsbTerminalTypeDiscriminants) -> Result<Self, InputTerminalEntityParseError>
	{
		Ok(InputTerminalType::Common(CommonTerminalType::Usb(Self::construct(entity_body, usb_terminal_type, |cause| InputTerminalEntityParseError::CanNotAllocateMemoryForUsbTerminalType { usb_format_type, cause })?)))
	}
	
	#[inline(always)]
	fn external(entity_body: &[u8], external_terminal_type: impl FnOnce(Vec<u8>) -> ExternalTerminalType, external_format_type: ExternalTerminalTypeDiscriminants) -> Result<Self, InputTerminalEntityParseError>
	{
		Ok(InputTerminalType::Common(CommonTerminalType::External(Self::construct(entity_body, external_terminal_type, |cause| InputTerminalEntityParseError::CanNotAllocateMemoryForExternalTerminalType { external_format_type, cause })?)))
	}
	
	#[inline(always)]
	fn output_error(output_specific_terminal_type: OutputSpecificTerminalTypeDiscriminants) -> Result<Self,InputTerminalEntityParseError>
	{
		Err(InputTerminalEntityParseError::OutputTerminalType { output_specific_terminal_type })
	}
	
	#[inline(always)]
	fn construct<TerminalType, Constructor: FnOnce(Vec<u8>) -> TerminalType, Error: FnOnce(TryReserveError) -> InputTerminalEntityParseError>(entity_body: &[u8], constructor: Constructor, error: Error) -> Result<TerminalType, InputTerminalEntityParseError>
	{
		Self::data(entity_body, error).map(|data| constructor(data))
	}
	
	#[inline(always)]
	fn data<E: error::Error, Error: FnOnce(TryReserveError) -> E>(entity_body: &[u8], error: Error) -> Result<Vec<u8>, E>
	{
		Vec::new_from(entity_body.get_unchecked_range_safe((InputTerminalEntity::MinimumBLength - DescriptorEntityMinimumLength) .. )).map_err(error)
	}
}
