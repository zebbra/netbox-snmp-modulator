from django.db import migrations, models


class Migration(migrations.Migration):

    initial = True

    dependencies = []

    operations = [
        migrations.CreateModel(
            name="Modulator",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
            ],
            options={
                "default_permissions": (),
                "permissions": (
                    ("use_modulator", "Can view SNMP Modulator rules and device results"),
                    ("run_modulator", "Can run SNMP Modulator probes and apply them"),
                ),
            },
        ),
    ]
