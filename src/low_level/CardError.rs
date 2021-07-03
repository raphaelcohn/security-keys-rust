// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


#[allow(missing_docs)]
#[derive(Debug, Clone, Eq, PartialEq)]
pub(super) enum CardError
{
	OutOfMemoryAllocatingBuffer(TryReserveError),
	
	StartTransaction(pcsc::Error),

	StatusLength(pcsc::Error),
	
	GetStatus(pcsc::Error),

	GetAttributeLength(pcsc::Error),
	
	GetAttribute(pcsc::Error),
	
	SetAttribute(pcsc::Error),

	Control(pcsc::Error),
	
	Finish(pcsc::Error),
	
	Transmit(pcsc::Error),
	
	TransmitReturnedLessThanTwoBytes
	{
		received_length: u8
	},
	
	TransmitReturnedError
	{
		error_code: u16,
	},

	TransmitCardOutOfMemory,
	
	TransmitCardLiedAboutSupportingChainedCommands,

	TransmitChunkOtherThanFinalHadUnexpectedError(ResponseCode),
	
	TransmitChunkOtherThanFinalHadResponseData
	{
		data_length: usize
	},
}

impl Display for CardError
{
	fn fmt(&self, f: &mut Formatter) -> fmt::Result
	{
		write!(f, "{}:", self.to_string())?;
		
		use self::CardError::*;
		match self
		{
			OutOfMemoryAllocatingBuffer(cause) => write!(f, "{}", cause),
			
			StartTransaction(cause) => write!(f, "{}", cause),
			
			StatusLength(cause) => write!(f, "{}", cause),
			
			GetStatus(cause) => write!(f, "{}", cause),
			
			GetAttributeLength(cause) => write!(f, "{}", cause),
			
			GetAttribute(cause) => write!(f, "{}", cause),
			
			SetAttribute(cause) => write!(f, "{}", cause),
			
			Control(cause) => write!(f, "{}", cause),
			
			Finish(cause) => write!(f, "{}", cause),
			
			Transmit(cause) => write!(f, "{}", cause),
			
			TransmitReturnedLessThanTwoBytes { received_length } => write!(f, "{}", received_length),
			
			TransmitReturnedError { error_code: result_code } => write!(f, "{}", result_code),
			
			TransmitCardOutOfMemory => write!(f, "()"),
			
			TransmitCardLiedAboutSupportingChainedCommands => write!(f, "()"),
			
			TransmitChunkOtherThanFinalHadUnexpectedError(response_code) => write!(f, "{:?}", response_code),
			
			TransmitChunkOtherThanFinalHadResponseData { data_length } => write!(f, "{}", data_length),
		}
	}
}

impl error::Error for CardError
{
	#[inline(always)]
	fn source(&self) -> Option<&(dyn error::Error + 'static)>
	{
		use self::CardError::*;
		match self
		{
			OutOfMemoryAllocatingBuffer(cause) => Some(cause),
			
			StartTransaction(cause) => Some(cause),
			
			StatusLength(cause) => Some(cause),
			
			GetStatus(cause) => Some(cause),
			
			GetAttributeLength(cause) => Some(cause),
			
			GetAttribute(cause) => Some(cause),
			
			SetAttribute(cause) => Some(cause),
			
			Control(cause) => Some(cause),
			
			Finish(cause) => Some(cause),
			
			Transmit(cause) => Some(cause),
			
			TransmitReturnedLessThanTwoBytes { .. } => None,
			
			TransmitReturnedError { .. } => None,
			
			TransmitCardOutOfMemory => None,
			
			TransmitCardLiedAboutSupportingChainedCommands => None,
			
			TransmitChunkOtherThanFinalHadUnexpectedError(..) => None,
			
			TransmitChunkOtherThanFinalHadResponseData { .. } => None,
		}
	}
}

impl From<TryReserveError> for CardError
{
	#[inline(always)]
	fn from(cause: TryReserveError) -> Self
	{
		CardError::OutOfMemoryAllocatingBuffer(cause)
	}
}
