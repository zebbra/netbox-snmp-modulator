from django.utils.translation import gettext_lazy as _
from netbox.plugins import PluginMenu, PluginMenuItem

menu = PluginMenu(
    label=_("SNMP Modulator"),
    icon_class="mdi mdi-tune-variant",
    groups=(
        (
            _("SNMP Modulator"),
            (
                PluginMenuItem(
                    link="plugins:netbox_snmp_modulator:rules",
                    link_text=_("Rules"),
                    permissions=["netbox_snmp_modulator.use_modulator"],
                ),
                PluginMenuItem(
                    link="plugins:netbox_snmp_modulator:bulk",
                    link_text=_("Bulk"),
                    permissions=["netbox_snmp_modulator.run_modulator"],
                ),
            ),
        ),
        (
            _("Status"),
            (
                PluginMenuItem(
                    link="plugins:netbox_snmp_modulator:status",
                    link_text=_("Backend"),
                    permissions=["netbox_snmp_modulator.use_modulator"],
                ),
            ),
        ),
    ),
)
