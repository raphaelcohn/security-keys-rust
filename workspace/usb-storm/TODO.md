* Windows OS Descriptors
  * Query Version 1.0
  * Query Version 2.0
* HID
  * Parse all report Usages into actual values based on HUT 1.22
  * Pass in a custom allocator
    * This will not work with IndexMap and IndexSet, but it's a start.
  * Limit global stack
    * Linux uses HID_GLOBAL_STACK_SIZE, which is 4, for the global state table.
  * Cap collection depth
  * Usages pages should not change in a range.
  * Usage page should not be 0x0000
  * Linux caps usages and collections count at HID_MAX_USAGES
* Video (Versions 1.0, 1.1 and 1.5)
  * Video Control End Points
  * Video Streaming Interfaces
  * Video Streaming End Points
* Audio
  * MIDI Version 1 and 2
* Comms
  * Add support for TrueRNG2
