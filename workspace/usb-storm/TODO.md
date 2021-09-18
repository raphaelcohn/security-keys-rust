* Windows OS Descriptors
  * Query Version 1.0
  * Query Version 2.0
* HID
  * Parse all report Usages into actual values based on HUT 1.22
  * Pass in a custom allocator
    * This will not work with IndexMap and IndexSet, but it's a start.
  * Collections have additional constraints.
    * ?Application Collections can only be declared at top level
    * ?Report Collection must have an unique ReportIdentifier
    * Named Array Collections can only contain 'Selector' usages.
* Video (Versions 1.0, 1.1 and 1.5)
  * Video Control End Points
  * Video Streaming Interfaces
  * Video Streaming End Points
* Audio
  * MIDI Version 1 and 2
* Comms
  * Add support for TrueRNG2
