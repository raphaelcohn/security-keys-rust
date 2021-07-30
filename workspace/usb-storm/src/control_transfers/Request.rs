// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// Transfer request.
#[derive(Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
#[repr(u8)]
pub enum Request
{
	#[allow(missing_docs)]
	GetStatus = LIBUSB_REQUEST_GET_STATUS,
	
	#[allow(missing_docs)]
	ClearFeature = LIBUSB_REQUEST_CLEAR_FEATURE,
	
	#[allow(missing_docs)]
	SetFeature = LIBUSB_REQUEST_SET_FEATURE,
	
	#[allow(missing_docs)]
	SetAddress = LIBUSB_REQUEST_SET_ADDRESS,
	
	#[allow(missing_docs)]
	GetDescriptor = LIBUSB_REQUEST_GET_DESCRIPTOR,
	
	#[allow(missing_docs)]
	SetDescriptor = LIBUSB_REQUEST_SET_DESCRIPTOR,
	
	#[allow(missing_docs)]
	GetConfiguration = LIBUSB_REQUEST_GET_CONFIGURATION,
	
	#[allow(missing_docs)]
	SetConfiguration = LIBUSB_REQUEST_SET_CONFIGURATION,
	
	#[allow(missing_docs)]
	GetInterface = LIBUSB_REQUEST_GET_INTERFACE,
	
	#[allow(missing_docs)]
	SetInterface = LIBUSB_REQUEST_SET_INTERFACE,
	
	#[allow(missing_docs)]
	SynchFrame = LIBUSB_REQUEST_SYNCH_FRAME,
	
	#[allow(missing_docs)]
	SelSEL = LIBUSB_REQUEST_SET_SEL,
	
	#[allow(missing_docs)]
	SetIsochronousDelay = LIBUSB_SET_ISOCH_DELAY,
}
