// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/raphaelcohn/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/raphaelcohn/security-keys-rust/master/COPYRIGHT.


extern "C"
{
	/// ***Only one thread at a time can call this for a particular `Lun`.***.
	///
	/// This function gets the slot or card capabilities for a particular.
	/// If you have only 1 card slot and don't mind loading a new driver for each reader then ignore `Lun`.
	///
	/// * `Lun`: Logical Unit Number.
	/// * `Tag`: Tag of the desired data value,
	/// * `Length`: Length of the desired data value.
	/// * `Value`: Value of the desired data.
	///
	///
	/// ## Tag values
	///
	/// These overlap with PC/SC attribute definitions.
	///
	/// * `TAG_IFD_ATR`: Return the ATR and its size (implementation is mandatory). Returns a byte array of upto `MAX_ATR_SIZE` bytes.
	/// * `TAG_IFD_SLOTNUM`: Unused / deprecated.
	/// * `SCARD_ATTR_ATR_STRING`: Not mandatory, but should returns the same data as `TAG_IFD_ATR`. Returns a byte array of upto `MAX_ATR_SIZE` bytes.
	/// * `TAG_IFD_SIMULTANEOUS_ACCESS`: Return the number of sessions (readers) the driver can handle. Returns an `u8`.
	/// * `TAG_IFD_THREAD_SAFE`: If the driver supports more than one reader (check `TAG_IFD_SIMULTANEOUS_ACCESS`), then this tag indicates if the driver supports access to multiple readers at the same time. If `0`, the driver does not support simultaneous access. If `1`, it does. Returns an `u8`.
	/// * `TAG_IFD_SLOTS_NUMBER`: Return the number of slots in this reader. Returns an `u8`.
	/// * `TAG_IFD_SLOT_THREAD_SAFE`: If the reader has more than one slot (check `TAG_IFD_SLOTS_NUMBER`) this tag indicates if the driver supports access to multiple slots of the same reader at the same time. if `0`, the driver supports only 1 slot access at a time. If `1`, the driver supports simultaneous slot accesses. Returns an `u8`.
	/// * `TAG_IFD_POLLING_THREAD`: Unused / deprecated.
	/// * `TAG_IFD_POLLING_THREAD_WITH_TIMEOUT`: If the driver provides a polling thread then `Value` is a function pointer to a function with C prototype `RESPONSECODE foo(DWORD Lun, int timeout)`.
	/// * `TAG_IFD_POLLING_THREAD_KILLABLE`: Tell if the polling thread can be killed. If the value is `0`, then the driver cannot be stopped using `pthread_cancel()`; the driver must then implement support for `TAG_IFD_STOP_POLLING_THREAD`. If the value is `1`, then the driver can be stopped using `pthread_cancel()`. ***NOTE: Some documentation refers to `pthread_kill()` instead of `pthread_cancel()`.***
	/// * `TAG_IFD_STOP_POLLING_THREAD`: Returns a function pointer in `Value` to a function used to stop the polling thread returned by `TAG_IFD_POLLING_THREAD_WITH_TIMEOUT`. The function's C prototype is `RESPONSECODE foo(DWORD Lun)`.
	///
	///
	/// ## Addtional Tag Values supportd by ifd-ccid.bundle (CCID)
	///
	/// * `SCARD_ATTR_ATR_STRING`: This is treated identically to `TAG_IFD_ATR`.
	/// * `SCARD_ATTR_ICC_INTERFACE_STATUS`: This returns a value of `1` if `IFDHICCPresence()` returns `IFD_ICC_PRESENT` or `0` otherwise (ie just call `IFDHICCPresence()` directly).
	/// * `SCARD_ATTR_ICC_PRESENCE`: This returns a value of `2` if `IFDHICCPresence()` returns `IFD_ICC_PRESENT` or `0` otherwise (ie just call `IFDHICCPresence()` directly).
	/// * `SCARD_ATTR_VENDOR_IFD_VERSION`: Returns a Binary Coded Decimal (BCD) of 4 bytes.
	/// * `SCARD_ATTR_VENDOR_NAME`: Byte buffer if manufacturer is known.
	/// * `SCARD_ATTR_VENDOR_IFD_SERIAL_NO`: Byte buffer if vendor is known.
	/// * `SCARD_ATTR_CHANNEL_ID`: Returns an `u32`; top 16 bits are 0x0020, bits 8-15 are bus number and bits 0-7 are address.
	/// * `SCARD_ATTR_MAXINPUT`: Returns an `u32`.
	/// * `TAG_IFD_SIMULTANEOUS_ACCESS`: This returns a value of `CCID_DRIVER_MAX_READERS`. Frustratingly it makes no use of `Lun` but can not be called until at least one `Lun` has been created by `IFDHCreateChannel()` or `IFDHCreateChannelByName()`.
	/// * `TAG_IFD_SLOTS_NUMBER`: Usually 1, but can be upto 8.
	/// * `TAG_IFD_THREAD_SAFE`: Always returns `0` on MacOS and `1` otherwise.
	///
	///
	/// # Return Codes
	///
	/// * `IFD_SUCCESS`: Successful.
	/// * `IFD_COMMUNICATION_ERROR`: Error has occurred.
	/// * `IFD_NO_SUCH_DEVICE`: The reader is no more present.
	/// * `IFD_ERROR_INSUFFICIENT_BUFFER`: Value buffer is too small.
	/// * `IFD_ERROR_TAG`: Unsupported tag given.
	pub(in crate::ifdhandler) fn IFDHGetCapabilities(Lun: DWORD, Tag: DWORD, Length: *mut DWORD, Value: *mut u8) -> RESPONSECODE;
}
