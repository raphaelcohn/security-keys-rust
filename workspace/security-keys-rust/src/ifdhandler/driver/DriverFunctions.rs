// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/raphaelcohn/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/raphaelcohn/security-keys-rust/master/COPYRIGHT.


/// # Logical Unit Number.
///
/// In PC/SC, `Lun` is also called a slot and maps to a reader context.
///
/// Use this for multiple card slots or multiple readers.
/// `0xXXXXYYYY - XXXX` multiple readers, `YYYY` multiple slots.
/// The resource manager will set these automatically.
/// By default the resource manager loads a new instance of the driver so if your reader does not have more than one smart card slot then ignore the Logical Unit Number in all functions.
/// PC/SC supports the loading of multiple readers through one instance of the driver in which `XXXX` is important.
/// `XXXX` identifies the unique reader in which the driver communicates to.
/// The driver should set up an array of structures that associate this `XXXX` with the underlying details of the particular reader.
#[derive(Debug, Clone)]
struct DriverFunctions
{
	IFDHCloseChannel: RawSymbol<unsafe extern fn(DWORD) -> RESPONSECODE>,
	
	IFDHControl: RawSymbol<unsafe extern fn(DWORD, DWORD, *const u8, DWORD, *mut u8, DWORD, *mut DWORD) -> RESPONSECODE>,
	
	IFDHCreateChannel: RawSymbol<unsafe extern fn(DWORD, DWORD) -> RESPONSECODE>,
	
	IFDHCreateChannelByName: RawSymbol<unsafe extern fn(DWORD, *const c_char) -> RESPONSECODE>,
	
	IFDHGetCapabilities: RawSymbol<unsafe extern fn(DWORD, DWORD, *mut DWORD, *mut u8) -> RESPONSECODE>,
	
	IFDHPowerICC: RawSymbol<unsafe extern fn(DWORD, DWORD, *mut u8, *mut DWORD) -> RESPONSECODE>,
	
	IFDHICCPresence: RawSymbol<unsafe extern fn(DWORD) -> RESPONSECODE>,
	
	IFDHSetCapabilities: RawSymbol<unsafe extern fn(DWORD, DWORD, *mut DWORD, *mut u8) -> RESPONSECODE>,
	
	IFDHSetProtocolParameters: RawSymbol<unsafe extern fn(DWORD, DWORD, u8, u8, u8, u8) -> RESPONSECODE>,
	
	IFDHTransmitToICC: RawSymbol<unsafe extern fn(DWORD, SCARD_IO_HEADER, *const u8, DWORD, *mut u8, *mut DWORD, *mut SCARD_IO_HEADER) -> RESPONSECODE>,
}

impl DriverFunctions
{
	const IgnoredChannel: DWORD = -1i32 as u32 as DWORD;
	
	/// ***Only one thread at a time can call this for a particular `Lun`.***.
	///
	/// This function should close the reader communication channel for the particular reader.
	/// Prior to closing the communication channel the reader should make sure the card is powered down and the terminal is also powered down.
	///
	/// * `Lun`: Logical Unit Number (also known as 'slot').
	///
	///
	/// # Return Codes
	///
	/// * `IFD_SUCCESS`: Successful.
	/// * `IFD_COMMUNICATION_ERROR`: Error has occurred.
	/// * `IFD_NO_SUCH_DEVICE`: The reader is no more present.
	#[inline(always)]
	fn IFDHCloseChannel(&self, Lun: DWORD) -> RESPONSECODE
	{
		unsafe { (self.IFDHCloseChannel)(Lun) }
	}
	
	/// ***Only one thread at a time can call this for a particular `Lun`.***.
	///
	/// This function performs a data exchange with the reader (not the card) specified by `Lun`.
	/// It is responsible for abstracting functionality such as PIN pads, biometrics, LCD panels, etc.
	/// You should follow the MCT (Multifunctional Card Terminal) and CTBCS specifications for a list of accepted commands to implement.
	/// This function is fully voluntary and does not have to be implemented unless you want extended functionality.
	///
	/// * `Lun`:  Logical Unit Number, also called `slot`.
	/// * `dwControlCode`:  Control code for the operation. This value identifies the specific operation to be performed. This value is driver specific.
	/// * `TxBuffer`:  Transmit data
	/// * `TxLength`:  Length of this buffer.
	/// * `RxBuffer`:  Receive data.
	/// * `RxLength`:  Length of the response buffer.
	/// * `pdwBytesReturned`:  Length of response.
	///
	/// This function will be passed the length of the buffer `RxBuffer` in `RxLength` and it must set the length of the received data in `pdwBytesReturned`.
	/// On error, `pdwBytesReturned` should be set to zero.
	///
	///
	/// ## Control codes supported by the ifd-ccd.bundle driver.
	///
	/// * `IOCTL_SMARTCARD_VENDOR_IFD_EXCHANGE`: Only if the driver option `DRIVER_OPTION_CCID_EXCHANGE_AUTHORIZED` is specified in the ifdDriverOptions in Info.plist.
	///* `CM_IOCTL_GET_FEATURE_REQUEST`  / `0x313520`: PC/SC v2.02.07 Part 10: Query for features.
	///* `IOCTL_FEATURE_IFD_PIN_PROPERTIES`: PC/SC v2.02.07 Part 10: Get PIN handling capabilities.
	///* `IOCTL_FEATURE_GET_TLV_PROPERTIES`: PC/SC v2.02.07 Part 10: Reader features.
	///* `IOCTL_FEATURE_VERIFY_PIN_DIRECT`: PC/SC v2.02.07 Part 10: Verify a PIN.
	///* `IOCTL_FEATURE_MODIFY_PIN_DIRECT`: PC/SC v2.02.07 Part 10: Modify a PIN.
	///* `IOCTL_FEATURE_MCT_READER_DIRECT`: PC/SC v2.02.07 Part 10: Multifunctional Card Terminal. The transmit buffer contains an Application Protocol Data Unit (APDU).
	///
	///
	/// ## Multifunctional Card Terminal (MCT) Application Protocol Data Unit (APDU).
	///
	/// * `CLA`: `0x20`.
	/// * `INS`:  One of:-
	/// 	* `0x70`: `SECODER INFO`.
	/// 	* `0x71`: `SECODER SELECT APPLICATION`.
	/// 	* `0x72`: `SECODER APPLICATION ACTIVE`.
	/// 	* `0x73`: `SECODER DATA CONFIRMATION`.
	/// 	* `0x74`: `SECODER PROCESS AUTHENTICATION TOKEN`.
	/// * `P1`: `0x00`.
	/// * `P2`: `0x00`.
	/// * `Lind`: `0x00`.
	///
	///
	/// ### Tag `IOCTL_FEATURE_GET_TLV_PROPERTIES`
	///
	/// This includes the following structures:-
	///
	/// * `PCSCv2_PART10_PROPERTY_wLcdLayout`.
	/// 	* Always present (but zero if no LCD).
	/// 	* Value of USB `wLcdLayout`.
	/// 	* Always little-endian u16 (even on big-endian machines).
	/// 	* `PCSCv2_PART10_PROPERTY_wLcdMaxCharacters`.
	/// 		* Present if `PCSCv2_PART10_PROPERTY_wLcdLayout` is non-zero.
	/// 		* Value of USB `wLcdLayout & 0xFF`.
	/// 		* Always little-endian u16 (even on big-endian machines).
	/// 	* `PCSCv2_PART10_PROPERTY_wLcdMaxLines`.
	/// 		* Present if `PCSCv2_PART10_PROPERTY_wLcdLayout` is non-zero.
	/// 		* Value of USB `wLcdLayout >> 8`.
	/// 		* Always little-endian u16 (even on big-endian machines).
	/// * `PCSCv2_PART10_PROPERTY_bTimeOut2`.
	/// 	* Always present.
	/// 	* Value always `0`.
	/// 	* u8.
	/// * `PCSCv2_PART10_PROPERTY_sFirmwareID`
	/// 	* Present for vendor `VENDOR_GEMALTO`.
	/// 	* Variable length up to 256 bytes.
	/// * `PCSCv2_PART10_PROPERTY_bMinPINSize` and `PCSCv2_PART10_PROPERTY_bMaxPINSize`.
	/// 	* Present and hardcoded for:-
	/// 		* vendor and product `GEMPCPINPAD` with USB `bcdDevice` of `0x0100.
	/// 		* vendor and product `VEGAALPHA`.
	/// 		* vendor and product `CHERRYST2000`.
	/// 		* vendor and product `CHERRY_KC1000SC`.
	/// 		* vendor and product `HID_OMNIKEY_3821`.
	/// 	* Present and variable for:-
	/// 		* Gemalto 'gemalto_firmware_features'
	/// 	* Always an u8.
	/// * `PCSCv2_PART10_PROPERTY_bEntryValidationCondition` (validation key pressed).
	/// 	* Present and hardcoded for:-
	/// 		* vendor and product `GEMPCPINPAD` with USB `bcdDevice` of `0x0100.
	/// 		* vendor and product `VEGAALPHA`.
	/// 		* vendor and product `CHERRYST2000`.
	/// 		* ***Not supported*** for `CHERRY_KC1000SC` or `HID_OMNIKEY_3821`.
	/// 	* Present and variable for:-
	/// 		* Gemalto 'gemalto_firmware_features'
	/// 	* Always an u8.
	/// * `PCSCv2_PART10_PROPERTY_bPPDUSupport`.
	/// 	* Always present.
	/// 	* Value always either `0` or `1`; reflects whether `DRIVER_OPTION_CCID_EXCHANGE_AUTHORIZED` has been specified in `Info.plist`.
	/// 	* u8.
	/// * `PCSCv2_PART10_PROPERTY_wIdVendor`
	/// 	* Always present.
	/// 	* USB Vendor Identifier.
	/// 	* Always little-endian u16 (even on big-endian machines).
	/// * `PCSCv2_PART10_PROPERTY_wIdProduct`
	/// 	* Always present.
	/// 	* USB Product Identifier.
	/// 	* Always little-endian u16 (even on big-endian machines).
	/// * `PCSCv2_PART10_PROPERTY_dwMaxAPDUDataSize`
	/// 	* Always present.
	/// 	* Zero unless USB dwFeatures supports `CCID_CLASS_EXTENDED_APDU` or `CCID_CLASS_TPDU`, in which case it is 65,536.
	/// 	* Always little-endian u32 (even on big-endian machines).
	///
	/// # Return Codes
	///
	/// * `IFD_SUCCESS`: Successful.
	/// * `IFD_COMMUNICATION_ERROR`: Error has occurred.
	/// * `IFD_NO_SUCH_DEVICE`: The reader is no more present.
	/// * `IFD_RESPONSE_TIMEOUT`: The response timed out.
	#[inline(always)]
	fn IFDHControl(&self, Lun: DWORD, dwControlCode: DWORD, TxBuffer: *const u8, TxLength: DWORD, RxBuffer: *mut u8, RxLength: DWORD, pdwBytesReturned: *mut DWORD) -> RESPONSECODE
	{
		unsafe { (self.IFDHControl)(Lun, dwControlCode, TxBuffer, TxLength, RxBuffer, RxLength, pdwBytesReturned) }
	}
	
	/// ***Only one thread at a time can call this for a particular `Lun`.***.
	///
	/// This function is required to open a communications channel to the port listed by `Channel`.
	/// For example, the first serial reader on `COM1` would link to `/dev/pcsc/1` which would be a symbolic link to`/dev/ttyS0` on some machines.
	/// This is used to help with inter-machine independence.
	///
	/// On machines with no `/dev` directory the driver writer may choose to map their Channel to whatever they feel is appropriate.
	///
	/// Once the channel is opened the reader must be in a state in which it is possible to query `IFDHICCPresence()` for card status.
	///
	/// USB readers can ignore the `Channel` parameter and query the USB bus for the particular reader by manufacturer (?vendor) identifier and product identifier.
	///
	/// * `Lun`:  Logical Unit Number, also called `slot`.
	/// * `Channel`: Channel Identifier; also called `port`.\*
	///
	/// \* Historically, this was used as follows:-
	///
	/// * `0x000001`: `/dev/pcsc/1`.
	/// * `0x000002`: `/dev/pcsc/2`.
	/// * `0x000003`: `/dev/pcsc/3`.
	/// * `0x000004`: `/dev/pcsc/4`.
	///
	///
	/// # Return Codes
	///
	/// * `IFD_SUCCESS`: Successful.
	/// * `IFD_COMMUNICATION_ERROR`: Error has occurred.
	/// * `IFD_NO_SUCH_DEVICE`: The reader is no more present.
	#[deprecated(note = "Use IFDHCreateChannelByName() function instead")]
	#[inline(always)]
	fn IFDHCreateChannel(&self, Lun: DWORD, Channel: DWORD) -> RESPONSECODE
	{
		unsafe { (self.IFDHCreateChannel)(Lun, Channel) }
	}
	
	/// ***Only one thread at a time can call this for a particular `Lun`.***.
	///
	/// This function is required to open a communications channel to the port listed by `DeviceName`.
	///
	/// Once the channel is opened the reader must be in a state in which it is possible to query `IFDHICCPresence()` for card status.
	///
	/// * `Lun`:  Logical Unit Number, also called `slot`.
	/// * `DeviceName`: 'Filename to use by the driver' or USB string; a non-null C String with a `strlen()` greater than 0.
	///
	///
	/// ## Device Name
	///
	/// For drivers configured by `/etc/reader.conf` (the legacy Gemplus Twin Serial drivers), this is the value of the field `DEVICENAME`. For USB drivers the `DeviceName` must start with `usb:VID/PID`, where:-
	///
	/// * `VID` is the Vendor Identifier as a 4 digit lowercase hexadecimal number;
	/// * `PID` is the Product Identifier as a 4 digit lowercase hexadecimal number.
	///
	/// For example, `usb:ab12/ff00`.
	///
	///
	/// ### Additional Information for USB card readers
	///
	/// The `DeviceName` string may also contain a more specialised identification string.
	///
	/// This additional information is used to differentiate between two identical readers connected at the same time. In this case the driver cannot differentiate the two readers using Vendor Identifier and Product Identifier and PID and must use some additional information identifying the USB port used by each reader.
	///
	/// This varies whether the driver uses `libusb` or `libudev`; the latter is the new default.
	/// If a driver does not understand the additional information, it should ignore it rather than fail.
	///
	///
	/// #### `libusb`
	///
	/// For USB drivers using libusb-1.0 http://libusb.sourceforge.net/ for USB abstraction the `DeviceName` the string may be generated by the C code `printf("usb:%04x/%04x:libusb-1.0:%d:%d:%d", idVendor, idProduct, bus_number, device_address, interface)`.
	///
	/// An example might be `usb:08e6/3437:libusb-1.0:7:99:0` under Linux (this may be different for Mac OS X).
	///
	///
	/// #### `libudev`
	///
	/// If using `libudev`, the string may be generated by the C code `printf("usb:%04x/%04x:libudev:%d:%s", idVendor, idProduct, bInterfaceNumber, devpath)` where:-
	///
	/// * `bInterfaceNumber` is the number of the interface on the device. It is only useful for devices with more than one CCID interface.
	/// * `devpath` is the filename of the device on the file system; it is obtained by the API function `udev_device_get_devnode()`.
	///
	/// An example might be `usb:08e6/3437:libudev:0:/dev/bus/usb/008/047` under Linux.
	///
	///
	/// # Return Codes
	///
	/// * `IFD_SUCCESS`: Successful.
	/// * `IFD_COMMUNICATION_ERROR`: Error has occurred.
	/// * `IFD_NO_SUCH_DEVICE`: The reader is no more present.
	#[inline(always)]
	fn IFDHCreateChannelByName(&self, Lun: DWORD, DeviceName: *const c_char) -> RESPONSECODE
	{
		unsafe { (self.IFDHCreateChannelByName)(Lun, DeviceName) }
	}
	
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
	#[inline(always)]
	fn IFDHGetCapabilities(&self, Lun: DWORD, Tag: DWORD, Length: *mut DWORD, Value: *mut u8) -> RESPONSECODE
	{
		unsafe { (self.IFDHGetCapabilities)(Lun, Tag, Length, Value) }
	}
	
	/// ***Only one thread at a time can call this for a particular `Lun`.***.
	///
	/// This function returns the status of the card inserted in the reader or slot specified by `Lun`.
	///
	/// In cases where the device supports asynchronous card insertion or removal detection, it is advised that the driver manages this through a thread so the driver does not have to send and receive a command each time this function is called.
	///
	/// * `Lun`: Logical Unit Number.
	///
	///
	/// @ingroup IFDHandler
	/// @param[in] Lun Logical Unit Number
	///
	///
	/// # Return Codes
	///
	/// * `IFD_SUCCESS`: Successful.
	/// * `IFD_COMMUNICATION_ERROR`: Error has occurred.
	/// * `IFD_NO_SUCH_DEVICE`: The reader is no more present.
	/// * `IFD_ICC_NOT_PRESENT`: ICC is not present.
	#[inline(always)]
	fn IFDHICCPresence(&self, Lun: DWORD) -> RESPONSECODE
	{
		unsafe { (self.IFDHICCPresence)(Lun) }
	}
	
	/// ***Only one thread at a time can call this for a particular `Lun`.***.
	///
	/// This function controls the power and reset signals of the smart card reader at the particular reader or slot specified by `Lun`.
	///
	/// * `Lun`: Logical Unit Number.
	/// * `Action`: Action to be taken on the card.
	/// * `Atr`: Answer to Reset (`ATR`) of the card. The driver is responsible for caching this value in case `IFDHGetCapabilities()` is called requesting the `ATR` and its length.
	/// * `AtrLength`: Length of the Answer to Reset. This value must not exceed `MAX_ATR_SIZE`.
	///
	///
	/// ## Actions
	///
	/// * `IFD_POWER_UP`: Power up the card (store and return `Atr` and `AtrLength`).
	/// * `IFD_POWER_DOWN`: Power down the card (`Atr` and `AtrLength` should be zeroed).
	/// * `IFD_RESET`:  Perform a warm reset of the card (no power down). If the card is not powered then power up the card (store and return `Atr` and `AtrLength`).
	///
	///
	/// ## Memory cards without an Answer to Reset (`ATR`).
	///
	/// These should return `IFD_SUCCESS` on reset but the `Atr` and `AtrLength` should be zeroed.
	///
	///
	/// ## Reset Errors
	///
	/// These should return zero for the `AtrLength` and return the error code `IFD_ERROR_POWER_ACTION`.
	///
	///
	/// # Return Codes
	///
	/// * `IFD_SUCCESS`: Successful.
	/// * `IFD_COMMUNICATION_ERROR`: Error has occurred.
	/// * `IFD_NO_SUCH_DEVICE`: The reader is no more present.
	/// * `IFD_ERROR_POWER_ACTION`: Error powering or resetting the card.
	/// * `IFD_NOT_SUPPORTED`: Action not supported.
	#[inline(always)]
	fn IFDHPowerICC(&self, Lun: DWORD, Action: DWORD, Atr: *mut u8, AtrLength: *mut DWORD) -> RESPONSECODE
	{
		unsafe { (self.IFDHPowerICC)(Lun, Action, Atr, AtrLength) }
	}
	
	/// This function should set the slot or card capabilities for a particular slot or card.
	/// If you have only 1 card slot and don't mind loading a new driver for each reader then ignore `Lun`.
	///
	///
	/// * `Lun`: Logical Unit Number.
	/// * `Tag`: Tag of the desired data value,
	/// * `Length`: Length of the desired data value.
	/// * `Value`: Value of the desired data.
	///
	/// ## Tag values
	///
	/// These overlap with PC/SC attribute definitions.
	/// There are not explicitly defined `TAG_IFD_*` values that are general across drivers.
	///
	///
	/// ## Addtional Tag Values supportd by ifd-ccid.bundle (CCID)
	///
	/// The ifd-ccid driver does not support any tags at all, and returns `IFD_NOT_SUPPORTED` (in violation of the documented behaviour) unless the `Lun` is invalid, in which case, it returns `IFD_COMMUNICATION_ERROR`.
	///
	///
	/// # Return Codes
	///
	/// * `IFD_SUCCESS`: Successful.
	/// * `IFD_COMMUNICATION_ERROR`: NOT DOCUMENTED, but used in practice for an invalid Lun.
	/// * `IFD_NO_SUCH_DEVICE`: The reader is no more present.
	/// * `IFD_ERROR_TAG`: Invalid (?unsupported) tag given.
	/// * `IFD_ERROR_SET_FAILURE`: Could not set value.
	/// * `IFD_ERROR_VALUE_READ_ONLY`: Trying to set a read only value.
	/// * `IFD_NOT_SUPPORTED`:  NOT DOCUMENTED, but used in practice.
	#[inline(always)]
	fn IFDHSetCapabilities(&self, Lun: DWORD, Tag: DWORD, Length: *mut DWORD, Value: *mut u8) -> RESPONSECODE
	{
		unsafe { (self.IFDHSetCapabilities)(Lun, Tag, Length, Value) }
	}
	
	/// This function should set the Protocol Type Selection (PTS) of a particular card/slot using the three PTS parameters sent.
	///
	/// * `Lun`: Logical Unit Number.
	/// * `Protocol`: Desired protocol, typically `SCARD_PROTOCOL_T0` or `SCARD_PROTOCOL_T1`.
	/// * `Flags`: Logical-or of possible values (`IFD_NEGOTIATE_PTS1`, `IFD_NEGOTIATE_PTS2` and `IFD_NEGOTIATE_PTS3`) to determine which Protocol Type Selection (PTS) to negotiate.
	/// * `PTS1`: First PTS Value`.
	/// * `PTS2`: Second PTS Value`.
	/// * `PTS3`: Third PTS Value`.
	///
	/// See ISO 7816 EMV specifications.
	///
	///
	/// # Return Codes
	///
	/// * `IFD_SUCCESS`: Successful.
	/// * `IFD_COMMUNICATION_ERROR`: Error has occurred.
	/// * `IFD_NO_SUCH_DEVICE`: The reader is no more present.
	/// * `IFD_ERROR_PTS_FAILURE`: Could not set PTS value.
	/// * `IFD_PROTOCOL_NOT_SUPPORTED`:  Protocol is not supported.
	/// * `IFD_NOT_SUPPORTED`: Action not supported.
	#[inline(always)]
	fn IFDHSetProtocolParameters(&self, Lun: DWORD, Protocol: DWORD, Flags: u8, PTS1: u8, PTS2: u8, PTS3: u8) -> RESPONSECODE
	{
		unsafe { (self.IFDHSetProtocolParameters)(Lun, Protocol, Flags, PTS1, PTS2, PTS3) }
	}
	
	/// ***Only one thread at a time can call this for a particular `Lun`.***.
	///
	/// This function performs an APDU exchange with the card or slot specified by Lun.
	///
	/// The driver is responsible for performing any protocol specific exchanges such as T=0, 1, etc.
	/// Calling this function will abstract all protocol differences.
	///
	/// * `Lun`: Logical Unit Number.
	/// * `SendPci`: A struct containing a `Protocol` field with a value from `0` to `14` inclusive, and an unused `Length` field.
	/// * `TxBuffer`: A buffer containing a transmit Application Protocol Data Unit (APDU), eg `[0x00, 0xA4, 0x00, 0x00, 0x02, 0x3F, 0x00]`.
	/// * `TxLength`: Length of the `TxBuffer` buffer.
	/// * `RxBuffer`: A buffer to contain a receive Application Protocol Data Unit (APDU), eg `[0x61, 0x14]`.
	/// * `RxLength`: Length of the `RxBuffer` buffer; length of the received receive Application Protocol Data Unit (APDU). Must be zero if an error occurs.
	/// * `RecvPci`:  A struct containing a `Protocol` field with a value from `0` to `14` inclusive, and an unused `Length` field.
	///
	///
	/// ## PCI
	///
	/// In the above function parameters 'Pci' has nothing to do with the PCI interface, but instead stands for Protocol Control Information.
	///
	///
	/// ## Memory Cards
	///
	/// The driver is responsible for knowing what type of card it has.
	/// If the current slot or card contains a memory card then this command should ignore  the Protocol and use the MCT (Multifunctional Card Terminal) style commands for support for these style cards and transmit them appropriately.
	/// If your reader does not support/ memory cards or you don't want to implement this functionality, then ignore this.
	///
	///
	/// ## Get Response Application Protocol Data Unit.
	///
	/// The driver is not responsible for doing an automatic Get Response command for received buffers with a status code of `0x61 0xXX`.
	///
	///
	/// # Return Codes
	///
	/// * `IFD_SUCCESS`: Successful.
	/// * `IFD_COMMUNICATION_ERROR`: Error has occurred.
	/// * `IFD_NO_SUCH_DEVICE`: The reader is no more present.
	/// * `IFD_ICC_NOT_PRESENT`: ICC is not present.
	/// * `IFD_RESPONSE_TIMEOUT`:  The response timed out.
	/// * `IFD_NOT_SUPPORTED`:  ?Transmission of APDUs is unsupported, or the chosen SendPci protocol is not supported?
	#[inline(always)]
	fn IFDHTransmitToICC(&self, Lun: DWORD, SendPci: SCARD_IO_HEADER, TxBuffer: *const u8, TxLength: DWORD, RxBuffer: *mut u8, RxLength: *mut DWORD, RecvPci: *mut SCARD_IO_HEADER) -> RESPONSECODE
	{
		unsafe { (self.IFDHTransmitToICC)(Lun, SendPci, TxBuffer, TxLength, RxBuffer, RxLength, RecvPci) }
	}
	
	#[inline(always)]
	fn load(library_file_path: PathBuf) -> Result<Self, LoadDriverError>
	{
		let library = unsafe { Library::new(library_file_path)? };
		
		use KnownSymbolName::*;
		
		let this = Self
		{
			IFDHCloseChannel: IFDHCloseChannel.get_symbol(&library)?,
			
			IFDHControl: IFDHControl.get_symbol(&library)?,
			
			IFDHCreateChannel: IFDHCreateChannel.get_symbol(&library)?,
			
			IFDHCreateChannelByName: IFDHCreateChannelByName.get_symbol(&library)?,
			
			IFDHGetCapabilities: IFDHGetCapabilities.get_symbol(&library)?,
			
			IFDHICCPresence: IFDHICCPresence.get_symbol(&library)?,
			
			IFDHPowerICC: IFDHPowerICC.get_symbol(&library)?,
			
			IFDHSetCapabilities: IFDHSetCapabilities.get_symbol(&library)?,
			
			IFDHSetProtocolParameters: IFDHSetProtocolParameters.get_symbol(&library)?,
			
			IFDHTransmitToICC: IFDHTransmitToICC.get_symbol(&library)?,
		};
		
		forget(library);
		
		Ok(this)
	}
}
