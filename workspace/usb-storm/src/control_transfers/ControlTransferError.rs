// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// A control transfer error.
#[derive(Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
pub enum ControlTransferError
{
	/// `LIBUSB_ERROR_IO`.
	TransferInputOutputErrorOrTransferCancelled,
	
	/// `LIBUSB_ERROR_NO_DEVICE`.
	DeviceDisconnected,
	
	/// `LIBUSB_ERROR_TIMEOUT`.
	TimedOut(Duration),
	
	/// `LIBUSB_ERROR_OVERFLOW`.
	BufferOverflow,
	
	/// `LIBUSB_ERROR_PIPE`.
	///
	/// Internally, this is an USB `STALL`.
	ControlRequestNotSupported,
	
	/// `LIBUSB_ERROR_NO_MEM`.
	OutOfMemory,
	
	/// A value between -13 and -98 inclusive.
	NewlyDefined(i32),
	
	/// `LIBUSB_ERROR_OTHER`.
	Other,
}

impl Display for ControlTransferError
{
	#[inline(always)]
	fn fmt(&self, f: &mut Formatter) -> fmt::Result
	{
		Debug::fmt(self, f)
	}
}

impl error::Error for ControlTransferError
{
}
