from django.db import models


class Modulator(models.Model):
    """Never written to: only carries the plugin's permissions. The model name
    must match the codename tail ("use_modulator" -> action "use", model
    "modulator"), and it is managed so NetBox's /core/system row count works
    (see netbox_lens.models.Lens)."""

    class Meta:
        default_permissions = ()
        permissions = (
            ("use_modulator", "Can view SNMP Modulator rules and device results"),
            ("run_modulator", "Can run SNMP Modulator probes and apply them"),
        )
