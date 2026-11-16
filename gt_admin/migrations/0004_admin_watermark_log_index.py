from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [("gt_admin", "0003_adminauditlog_alter_report_content_type")]

    operations = [
        migrations.AddIndex(
            model_name="adminauditlog",
            index=models.Index(fields=["watermark_id", "-id"], name="admin_watermark_log_idx"),
        ),
    ]
