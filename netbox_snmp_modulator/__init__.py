from netbox.plugins import PluginConfig


class SnmpModulatorConfig(PluginConfig):
    name = "netbox_snmp_modulator"
    verbose_name = "SNMP Modulator"
    description = "Rules, per-device preview and bulk runs of the SNMP Exporter Modulator"
    version = "0.1.1"
    author = "Stefan Grosser"
    author_email = "stefan.grosser@zebbra.ch"
    base_url = "snmp-modulator"
    min_version = "4.0.0"
    default_settings = {
        "url": "",
        "token": "",
        "verify_ssl": True,
        # /probe waits for the result; longer than the modulator's own 60 s wait
        "timeout": 90,
        "status_timeout": 15,
        # device tag the modulator never touches (its mapping.yaml pin_tag)
        "pin_tag": "pin-snmp",
        # device CFs the modulator writes
        "module_cf": "snmp_exporter_module",
        "auth_cf": "snmp_auth_profile",
        "last_updated_cf": "snmp_modulator_last_updated",
        # device roles that get the SNMP Modulator card on the device page
        "device_panel_roles": ["router", "firewall", "border-firewall", "lwapp-ctr", "switch"],
        # roles left out of the bulk presets (no SNMP of their own)
        "bulk_exclude_roles": ["lwapp-ap"],
        # timestamps without a time zone are read as this
        "naive_timezone": "UTC",
    }


config = SnmpModulatorConfig
