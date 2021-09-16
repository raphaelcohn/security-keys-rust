# usb-storm

[usb-storm] is a modern USB descriptor parser designed to provide a rich, robust and secure domain model for USB device descriptors. It includes extremely extensive validation and checks, and is intended to be defensive in the presence of malicious USB devices. It is intended to serve as a superior replacement to [usbutils](https://github.com/gregkh/usbutils) [RDD!](https://sourceforge.net/projects/hidrdd/) and a much higher level wrapper than [rusb](https://github.com/a1ien/rusb). It provides unparalleled, meaningful insight into the USB devices attached to your system. In particular, it comprehensively decodes additional ('extra') descriptors for hubs, mice, smart cards, printers, storage devices and more.

[usb-storm] includes a full USB HID (Human Interface Descriptor) report parser and domain model, suitable in the future for OS development.

The domain model is serializable and deserializable using [serde](https://serde.rs).

[usb-storm] can be used as a library or a standalone (statically-linked) binary.

Lastly, please note that [usb-storm] requires Rust nightly (currently `nightly-2021-05-26`); this is unlikely to change until Rust stabilizes important features without which is it not possible to write performant programs which are defensive in the face of out-of-memory situations.


## Features

* Support for many device classes and extensions:-
  * USB hubs.
  * USB 3.1 SuperSpeed and USB 3.2 SuperSpeedPlus.
  * Binary Object Store.
  * Microsoft OS Descriptors 1.0 detection.
  * Microsoft OS Descriptors 2.0 detection.
  * Firmware Upgrade.
  * Printers (including Internet Printing).
  * Human Interace Device (HID), including report descriptors.
  * Smart Cards.
* Serialization of USB device domain model to human readable reports in
  * YAML
  * JSON
    * Condensed
    * Pretty
  * RON
  * LISP s-expressions
  * A simple Rust-like structure
* Incredibly comprehensive array of errors - no C-like 'ENOFILE' like translations.
  * Errors are serializable, so it is possible to send USB device failure reports remotely in the future.
* Extensive memory allocation checking, recursion checking and the like.
* Useful as a library.
* Statically-link
* Highly performant with aggresive avoidance of heap memory reallocations.


## Possible Future Additional Descriptors

If you have devices supporting the following and want to know more:-

* Microsoft OS Descriptors 1.0.
* Microsoft OS Descriptors 2.0.
* Human Interface Device Physical Descriptors
* Audio MIDI 1.0 and 2.0
* Communications devices.


## Long-Term Future Direction

It is intended to extend [usb-storm] in three different directions:-

* Firstly, to provide a modern replacement for the poor-quality Smart Card libraries in C, eg PCSC.
* Secondly, to progressively replace the C [libusb] library with a robust, modern Rust equivalent with far better memory management.
  * This will initially focus on Linux and MacOS.
* Lastly, to provide a framework for validating devices against specifications.


## Thanks

Many thanks to the authors of the [pcsc Rust crate](https://crates.io/crates/pcsc) and the [openpgp-card Rust crate](https://crates.io/crates/openpgp-card).


## Licensing

The license for this project is MIT.

The standalone binary statically-links to some LGPL code from a third party ([libusb]). It is the author's opinion that the LPGL's static linking limitations do not alter the License of this code, but legal opinions differ. Until the situation is tried in an English court, it's a grey area. However, this is an additional motivation to eliminate [libusb] from the dependencies.


[usb-storm]: https://github.com/raphaelcohn/security-keys-rust "security-keys-rust GitHub page"
[libusb]: https://libusb.info/ "libusb home page"
