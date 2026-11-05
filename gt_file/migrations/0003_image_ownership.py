from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [("gt_file", "0002_retire_airdrop")]

    operations = [
        migrations.AlterField(model_name="image", name="md5", field=models.CharField(max_length=32)),
        migrations.AddConstraint(
            model_name="image",
            constraint=models.UniqueConstraint(fields=("user", "md5"), name="unique_image_hash_per_user"),
        ),
    ]
