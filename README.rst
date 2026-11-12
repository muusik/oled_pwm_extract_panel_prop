Proper PWM brightness for legacy OLED pannels on an Intel GPU
=============================================================

Reverse engineered from the Windows Driver. Thanks Lenovo for including the debugging symbols in your driver
package so that even a reverse engineering illiterate like me can do it.

If your computer has an OLED screen and meets one of the following criteria, there's a chance that this
driver might work for you:

 - Your computer is released between 2015-2018, has an Intel processor and uses its integrated GPU.
 - The ``.inf`` file in the Windows driver package for your computer's OLED panel contains the following text: ``AOR``, ``DELVSS``, ``BrightLevelForACL``, and ``ACLCutoffAndDelta``.

This repository contains the required kernel patches and tools to generate the firmware used by the driver.

 - ``linux-legacy-oled-brightness.patch``: The patch itself. Sorry I didn't bother writing a proper commit message.
 - ``gen_panel_prop.py``: Generates ``intel_legacy_panel_data.bin``, a firmware file required by the driver.
 - ``extract_panel_prop.py``: Generates the same file from the Windows driver package instead, so it holds
   none of the panel's values itself (MIT). Give it the package's ``.exe`` (needs ``innoextract``), the
   unpacked directory, or ``PanelDriver.inf`` and ``PanelDriver.sys``. For the X1 Yoga 1st and 2nd gen that
   is Lenovo's ``n1fdl04w`` or ``n1ndp03w``; both contain the same ``PanelDriver.sys``.
 - ``download_panel_prop.sh``: Downloads ``n1ndp03w`` (or ``n1fdl04w``) from Lenovo, checks its SHA-256 and
   runs ``extract_panel_prop.py`` on it.

`Read this for more information, I guess. <https://chrisoft.org/blog/post/2025-04-28.html>`_

Instructions for ThinkPad X1 Yoga 1st gen / 2nd gen:

 1. Run ``gen_panel_prop.py`` (or ``download_panel_prop.sh``) to generate ``intel_legacy_panel_data.bin``. Put the generated file in your
    firmware directory (and if needed, your initramfs).
 2. Patch the sources for the kernel of your choice. Compile and install it.
 3. Boot your new kernel with an additional kernel parameter ``i915.enable_dpcd_backlight=99``. Check if it works.

Instructions for other laptops:

To be written

This repo will be updated at the same pace as my local system updates (i.e. pretty much randomly) as long as I
still have the laptop and haven't been frustrated with it.
