// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


#[derive(Default, Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
pub(crate) struct Device;

impl DeviceOrInterface for Device
{
}

#[allow(dead_code)]
impl Device
{
	/// See <https://www.usb.org/defined-class-codes#anchor_BaseClass00h>.
	const UseClassInformationInTheInterfaceDescriptorsClass: u8 = 0x00;
	const UseClassInformationInTheInterfaceDescriptorsSubClass: u8 = 0x00;
	const UseClassInformationInTheInterfaceDescriptorsProtocol: u8 = 0x00;
	
	/// See <https://www.usb.org/defined-class-codes#anchor_BaseClass09h>.
	const HubClass: u8 = 0x09;
	
	/// See <https://www.usb.org/defined-class-codes#anchor_BaseClass11h>.
	const BillboardDeviceClass: u8 = 0x12;
	
	const BillboardDeviceSubClass: u8 = 0x00;
	
	const BillboardDeviceProtocol: u8 = 0x00;
}
