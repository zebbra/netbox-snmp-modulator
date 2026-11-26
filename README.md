# netbox-snmp-modulator

NetBox plugin for the [SNMP Exporter Modulator](https://github.com/zebbra/netbox-snmp-exporter-modulator), for users without access to the modulator itself.

- **Rules:** the modulator's rules (`GET /rules`) as a readable table.
- **Device card:** which rules a device matches and what they add up to (`GET /rules/match`, modulator 1.12.2+), with «Preview» (dry run) and «Apply now».
- **Bulk:** dry run and apply over a device filter or the ticked devices of the device list, batch by batch (`/probe/run`).

## Install

```python
PLUGINS = ["netbox_snmp_modulator"]
PLUGINS_CONFIG = {
    "netbox_snmp_modulator": {
        "url": "http://snmp-modulator:8000",
        "token": "...",
    },
}
```

Then `manage.py migrate`. Other settings and their defaults: `netbox_snmp_modulator/__init__.py`.

Permissions: `netbox_snmp_modulator.use_modulator` (rules, backend status, device card) and `netbox_snmp_modulator.run_modulator` (preview, apply, bulk).

## Tests

Inside the NetBox container:

```sh
cd /opt/netbox/netbox && DJANGO_SETTINGS_MODULE=netbox.settings \
  /opt/netbox/venv/bin/python -m unittest discover -s /opt/netbox/netbox-snmp-modulator/tests
```
