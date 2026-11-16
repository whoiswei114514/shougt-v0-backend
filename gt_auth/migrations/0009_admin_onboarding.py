from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [('gt_auth', '0008_reader_and_dual_key')]
    operations = [migrations.AddField(
        model_name='user', name='admin_onboarding_required',
        field=models.BooleanField(default=False, verbose_name='待完成管理员首次配置'),
    )]
