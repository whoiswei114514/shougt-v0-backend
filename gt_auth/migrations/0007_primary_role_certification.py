from django.db import migrations, models
import django.db.models.deletion


def assign_primary_roles(apps, schema_editor):
    User = apps.get_model("gt_auth", "User")
    Role = apps.get_model("gt_auth", "Role")
    RoleMember = apps.get_model("gt_auth", "RoleMember")
    database = schema_editor.connection.alias

    for user in User.objects.using(database).order_by("pk").iterator():
        # Registration creates the public role before the anonymous one. Never
        # turn a shared/anonymous identity into a personal management identity.
        candidates = (Role.objects.using(database)
                      .filter(members__user_id=user.pk, members__is_owner=True,
                              is_private=False, is_shared=False, deleted=False)
                      .order_by("pk"))
        primary = next((role for role in candidates
                        if RoleMember.objects.using(database).filter(role_id=role.pk).count() == 1), None)
        if primary is None:
            primary = Role.objects.using(database).create(
                name=f"主角色{user.pk}"[:20], show_user_info=False,
            )
            RoleMember.objects.using(database).create(user_id=user.pk, role_id=primary.pk, is_owner=True)
        if user.hide_admin_badges:
            Role.objects.using(database).filter(pk=primary.pk).update(show_user_info=False)
        User.objects.using(database).filter(pk=user.pk).update(primary_role_id=primary.pk)


class Migration(migrations.Migration):
    dependencies = [("gt_auth", "0006_email_sender_identity")]

    operations = [
        migrations.AddField(
            model_name="user",
            name="primary_role",
            field=models.OneToOneField(
                blank=True, editable=False, null=True,
                on_delete=django.db.models.deletion.PROTECT,
                related_name="primary_user", to="gt_auth.role", verbose_name="注册主角色",
            ),
        ),
        migrations.RunPython(assign_primary_roles, migrations.RunPython.noop),
        migrations.RemoveField(model_name="user", name="hide_admin_badges"),
    ]
