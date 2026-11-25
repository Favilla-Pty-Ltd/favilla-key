#pragma once
struct RtcUsbConf { unsigned sw_hw_usb_phy_sel:1; unsigned sw_usb_phy_sel:1; };
struct RtcCntl { RtcUsbConf usb_conf; };
static RtcCntl RTCCNTL;
