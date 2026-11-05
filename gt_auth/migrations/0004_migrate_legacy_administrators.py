from django.db import migrations, models
from django.utils import timezone
from datetime import timedelta


def upgrade(apps, schema_editor):
    User = apps.get_model("gt_auth", "User")
    Permission = apps.get_model("gt_auth", "Permission")
    super_ids = User.objects.filter(is_superuser=True).values_list("permission_id", flat=True)
    Permission.objects.filter(pk__in=super_ids).update(super_admin=True)
    # Existing file managers retain access to both file and media inventories.
    Permission.objects.filter(admin_file=True).update(admin_image=True)
    User.objects.exclude(school="shou").update(school="external")
    for user in User.objects.select_related("permission").iterator():
        flags = [f.name for f in Permission._meta.fields if isinstance(f, models.BooleanField) and f.name != "no_review"]
        user.is_staff = user.is_superuser = user.permission.super_admin
        user.version += 1
        if any(getattr(user.permission, flag) for flag in flags):
            user.admin_candidate_until = timezone.now() + timedelta(days=30)
        user.save(update_fields=["is_staff", "is_superuser", "version", "admin_candidate_until"])


class Migration(migrations.Migration):
    dependencies = [("gt_auth", "0003_advancedverification_authsession_and_more")]
    operations = [migrations.RunPython(upgrade, migrations.RunPython.noop)]
