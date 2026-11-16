from django.conf import settings
from netbox.plugins import PluginTemplateExtension

from .views import RUN_PERM, USE_PERM, device_card_enabled


class DeviceModulatorCard(PluginTemplateExtension):
    """The SNMP Modulator card on the device page. Renders only a placeholder;
    the body comes from /rules/match via htmx, so the page never waits on it."""
    models = ["dcim.device"]

    def right_page(self):
        user = self.context["request"].user
        device = self.context["object"]
        if not user.has_perm(USE_PERM) or not device_card_enabled(device):
            return ""
        return self.render("netbox_snmp_modulator/device_card.html", extra_context={
            "mod_device": device, "mod_can_run": user.has_perm(RUN_PERM),
            "mod_has_ip": bool(device.primary_ip4_id),
        })


class DeviceListModulatorButton(PluginTemplateExtension):
    """SNMP Modulator button on the device list: the bulk page for the ticked
    devices, or for the list's current filter when none are ticked."""
    models = ["dcim.device"]

    def list_buttons(self):
        request = self.context["request"]
        if not request.user.has_perm(RUN_PERM):
            return ""
        return self.render("netbox_snmp_modulator/device_list_buttons.html", extra_context={
            "mod_filter_qs": request.GET.urlencode(),
        })


template_extensions = [DeviceModulatorCard, DeviceListModulatorButton]
