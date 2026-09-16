#!/system/bin/sh
ui_print "- Installing ReZygisk/LSPosed Soft-Reboot Guard"
set_perm "$MODPATH/emulated-soft-reboot.sh" 0 0 0755
ui_print "- No daemon started, no reboot invoked during install"
ui_print "- Runs only during KernelSU emulated soft reboot"
