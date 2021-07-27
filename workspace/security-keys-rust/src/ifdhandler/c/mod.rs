// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/raphaelcohn/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/raphaelcohn/security-keys-rust/master/COPYRIGHT.


//! ## Understanding the relationship between the PCSC and (CCID)(https://salsa.debian.org/rousseau/CCID.git) projects.
//!
//! * The PCSC project providers a daemon service (`pcscd`) that talks to card drivers and a client library (`libpcsclite`) that talks to the daemon service.
//! * The CCID project providers a particular card driver for USB CCID devices, and, optionally, a legacy Gemalto serial device.
//!
//! PC/SC functions are defined in the PCSC project C header, `src/PCSC/winscard.h`; they are implemented twice, once inside the daemon (in the PCSC project C file `src/winscard.c`) and once inside the client library (in PCSC project C file `src/winscard_clnt.c`).
//!
//! Card drivers are required to implement an API, the most recent version of which is 3 (`IFD_HVERSION_3_0`), dating from Summer 2004, which consists of functions defined in the PCSC project C header `src/PCSC/ifdhandler.h`.
//! These functions are typically of the form `RESPONSECODE FunctionName(DWORD Lun, ...)`, eg `RESPONSECODE IFDHCreateChannelByName(DWORD Lun, LPSTR DeviceName)`.
//! They return in the `RESPONSECODE` type return codes `IFD_*`, such as `IFD_SUCCESS` and `IFD_COMMUNICATION_ERROR`.
//!
//! These functions are bound dynamically and invoked late bound through function pointers on a `FctMap_V3` struct (in the PCSC project C header `src/reader_factory.h`).
//!
//! ```sh
//! ifdwrapper.c Function	FctMap_V3 Function Pointer		ifdhandler.h				PC/SC equivalent	Notes
//! IFDOpenIFD				pvfCreateChannel				IFDHCreateChannel			SCardConnect		?Legacy; should IFDHCreateChannelByName be preferred?
//! IFDOpenIFD				pvfCreateChannelByName			IFDHCreateChannelByName		SCardConnect		Uses READER_CONTEXT's device CString field if defined otherwise uses port field.
//! IFDCloseIFD				pvfCloseChannel					IFDHCloseChannel			SCardDisonnect		Uses READER_CONTEXT's slot field.
//! IFDSetPTS				pvfSetProtocolParameters		IFDHSetProtocolParameters						Optional. PTS = Protocol Type Selection.
//! IFDGetCapabilities		pvfGetCapabilities				IFDHGetCapabilities			?SCardGetCapability	Combines Attribute Identifiers with 'TAG's.
//! IFDSetCapabilities		pvfSetCapabilities				IFDHSetCapabilities			?SCardSetCapability	Combines Attribute Identifiers with 'TAG's.
//! IFDPowerICC				pvfPowerICC						IFDHPowerICC									Calls IFDStatusICC first
//! IFDStatusICC			pvfICCPresence					IFDHICCPresence				Card status			Adds SCARD_PRESENT and SCARD_UNKNOWN flags.
//! IFDTransmit				pvfTransmitToICC				IFDHTransmitToICC			SCardTransmit
//! IFDControl				pvfControl						IFDHControl					SCardControl
//! ```
//!
//! `ifdhandler.h` functions:-
//! ```sh
//! Function																											READER_CONTEXT fields		Notes
//!	RESPONSECODE IFDHCreateChannel(DWORD Lun, DWORD Channel);															(slot, port)
//! RESPONSECODE IFDHCreateChannelByName(DWORD Lun, LPSTR DeviceName);													(slot, device)				device is a C String with strlen() > 0
//! RESPONSECODE IFDHCloseChannel(DWORD Lun);																			(slot)
//! RESPONSECODE IFDHSetProtocolParameters(DWORD Lun, DWORD Protocol, UCHAR Flags, UCHAR PTS1, UCHAR PTS2, UCHAR PTS3);	(slot, (function args))
//! RESPONSECODE IFDHGetCapabilities(DWORD Lun, DWORD Tag, PDWORD Length, PUCHAR Value);								(slot, (function args))
//! RESPONSECODE IFDHSetCapabilities(DWORD Lun, DWORD Tag, DWORD Length, PUCHAR Value);									(slot, (function args))
//! RESPONSECODE IFDHPowerICC(DWORD Lun, DWORD Action, PUCHAR Atr, PDWORD AtrLength);									(slot, (function args))
//! RESPONSECODE IFDHICCPresence(DWORD Lun);																			(slot)
//! RESPONSECODE IFDHTransmitToICC(DWORD Lun, SCARD_IO_HEADER SendPci, PUCHAR TxBuffer, DWORD TxLength, PUCHAR RxBuffer, PDWORD RxLength, PSCARD_IO_HEADER RecvPci);	(slot, (function args))
//! RESPONSECODE IFDHControl(DWORD Lun, DWORD dwControlCode, PUCHAR TxBuffer, DWORD TxLength, PUCHAR RxBuffer, DWORD RxLength, LPDWORD pdwBytesReturned);				(slot)
//!
//! slot is -1 if the card reader was not opened successfully.
//! ```
//!
//! Dynamic loading can be achieved using the `https://github.com/nagisa/rust_libloading/` library.
//!
//! A usage pattern:-
//!
//! * hotplug RFAddReader
//! 	* PCSCLITE_HP_BASE_PORT is 0x200000
//! 	* mac os x HPScan
//! 		* only used if not using libusb
//! 		* readerName = a->m_driver->m_friendlyName
//! 		* port = PCSCLITE_HP_BASE_PORT + a->m_address
//! 		* library = a->m_driver->m_libPath
//! 		* device = deviceName = a->m_driver->m_friendlyName
//! 	* linux legacy
//! 		* only used if not using libusb or libudev
//! 		* NOT used on Alpine Linux
//! 		* readerName = bundleTracker[i].readerName
//! 		* port = PCSCLITE_HP_BASE_PORT + usbAddr
//! 		* library = bundleTracker[i].libraryPath
//! 		* deviceName = ""
//! 	* libusb
//! 		* only used if using libusb
//! 		* NOT used on Alpine Linux
//! 		* readerName =  readerTracker[i].fullName
//! 		* port = PCSCLITE_HP_BASE_PORT + index
//! 		* library = driver->libraryPath
//! 		* deviceName
//! 	* libudev
//! 		* only used if using libudev
//! 			* used eudev on Alpine Linux
//! 		* readerName = fullname / readerTracker[i].fullName
//! 		* port = PCSCLITE_HP_BASE_PORT + index
//! 		* library = driver->libraryPath
//! 		* deviceName
//!
//!  * Useful: pcsctest
//!
//! * RFAddReader - called from a hotplug_*.c context
//! 	* readerName, library, port and device passed in.
//! 		* readerName is, I think, a device driver name.
//! 		* library is used for dynamic loading with DYN_LoadLibrary
//! 		* device, with a fallback to port, is used to open the reader inside IFDOpenIFD - calls either IFDHCreateChannel or IFDHCreateChannelByName
//! 	* Initialize READER_CONTEXT
//! 		* RFSetReaderName
//!  			* slot: rContext->slot = i << 16; in RFSetReaderName
//! 			* slot is known as Lun.
//! 		* RFSetReaderName(sReadersContexts[dwContext], readerName, library, port)
//! 		* sReadersContexts[dwContext]->library = strdup(library);
//! 		* sReadersContexts[dwContext]->device = strdup(device);
//! 		* sReadersContexts[dwContext]->version = 0;
//! 		* sReadersContexts[dwContext]->port = port;
//! 		* sReadersContexts[dwContext]->mMutex = NULL;
//! 		* sReadersContexts[dwContext]->contexts = 0;
//! 		* sReadersContexts[dwContext]->pthThread = 0;
//! 		* sReadersContexts[dwContext]->hLockId = 0;
//! 		* sReadersContexts[dwContext]->LockCount = 0;
//! 		* sReadersContexts[dwContext]->vHandle = NULL;
//! 		* sReadersContexts[dwContext]->pFeeds = NULL;
//! 		* sReadersContexts[dwContext]->pMutex = NULL;
//! 		* sReadersContexts[dwContext]->pthCardEvent = NULL;
//! 		* Other sReadersContexts[dwContext] with defaults
//! 	* RFInitializeReader
//! 		* RFLoadReader(sReadersContexts[dwContext])	(dynload)
//!		 	* RFBindFunctions(sReadersContexts[dwContext]) (dynamically binds functions to functions pointers in sReadersContexts[dwContext])
//! 		* IFDOpenIFD
//! 			* Opens by device (name) if possible
//! 			* Otherwise opens by port


pub(in crate::ifdhandler) mod constants;


//pub(in crate::ifdhandler) mod functions;


pub(in crate::ifdhandler) mod structs;


pub(in crate::ifdhandler) mod types;
