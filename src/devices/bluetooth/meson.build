sources = files(
  'nm-bluez-device.c',
  'nm-bluez-manager.c',
  'nm-bluez4-adapter.c',
  'nm-bluez4-manager.c',
  'nm-bluez5-manager.c',
  'nm-bt-error.c',
  'nm-device-bt.c'
)

deps = [
  libnmdbus_dep,
  libnm_wwan_dep,
  nm_dep
]

ldflags = [
  '-Wl,--version-script,@0@'.format(linker_script_devices),
]

if enable_bluez5_dun
  sources += files('nm-bluez5-dun.c')

  deps += bluez5_dep
endif

libnm_device_plugin_bluetooth = shared_module(
  'nm-device-plugin-bluetooth',
  sources: sources,
  dependencies: deps,
  link_args: ldflags,
  link_depends: linker_script_devices,
  install: true,
  install_dir: nm_pkglibdir
)

core_plugins += libnm_device_plugin_bluetooth

run_target(
  'check-local-devices-bluetooth',
  command: [check_exports, libnm_device_plugin_bluetooth.full_path(), linker_script_devices],
  depends: libnm_device_plugin_bluetooth
)

# FIXME: check_so_symbols replacement
'''
check-local-devices-bluetooth: src/devices/bluetooth/libnm-device-plugin-bluetooth.la
  $(srcdir)/tools/check-exports.sh $(builddir)/src/devices/bluetooth/.libs/libnm-device-plugin-bluetooth.so "$(srcdir)/linker-script-devices.ver"
  $(call check_so_symbols,$(builddir)/src/devices/bluetooth/.libs/libnm-device-plugin-bluetooth.so)
'''
