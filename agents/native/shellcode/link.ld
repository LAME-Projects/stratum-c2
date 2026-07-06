/*
 * Flat binary linker script for x64 Windows shellcode.
 * All sections collapsed at offset 0 so RIP-relative refs to .rodata stay valid.
 * Output is a raw binary blob (no PE header).
 */
OUTPUT_FORMAT(binary)
ENTRY(_start)

SECTIONS
{
    . = 0;

    /* Entry stub first so the blob starts at offset 0 */
    .text : {
        *(.text._start)
        *(.text*)
    }

    /* Embedded script bytes and string literals immediately after code */
    .rodata : { *(.rodata*) }
    .data   : { *(.data*)   }

    /DISCARD/ : {
        *(.eh_frame*)
        *(.pdata*)
        *(.xdata*)
        *(.note*)
        *(.comment*)
        *(.bss*)
    }
}
