from django.db import migrations


class Migration(migrations.Migration):
    dependencies = [("gt_file", "0001_initial")]
    operations = [
        # Preserve historical rows and join tables for an operator-controlled archive.
        # There is no remaining application model, route, task or UI for airdrops.
        migrations.SeparateDatabaseAndState(
            database_operations=[],
            state_operations=[migrations.DeleteModel(name="Drop")],
        ),
    ]
