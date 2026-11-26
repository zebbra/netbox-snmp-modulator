from django.urls import path

from . import views

app_name = "netbox_snmp_modulator"

urlpatterns = [
    path("rules/", views.RulesView.as_view(), name="rules"),
    path("status/", views.StatusView.as_view(), name="status"),
    path("bulk/", views.BulkView.as_view(), name="bulk"),
    path("bulk/select/", views.BulkSelectView.as_view(), name="bulk_select"),
    path("bulk/run/", views.BulkRunPanelView.as_view(), name="bulk_run"),
    path("device/<int:pk>/card-data/", views.DeviceCardDataView.as_view(), name="device_card_data"),
    path("device/<int:pk>/probe/", views.ProbeView.as_view(), name="probe"),
    path("device/<int:pk>/apply/", views.ApplyView.as_view(), name="apply"),
]
