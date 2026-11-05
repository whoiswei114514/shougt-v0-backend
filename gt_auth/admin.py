from django.contrib import admin
from django.contrib.auth.models import Group
from .models import Quota, Permission, Privacy, User, TrustedUser, Role, RoleMember, Follow, Notification


class ReadOnlyAccountAdmin(admin.ModelAdmin):
    """Account changes are performed and audited in the certificate-protected app."""
    actions = None

    def has_add_permission(self, request):
        return False

    def has_change_permission(self, request, obj=None):
        return False

    def has_delete_permission(self, request, obj=None):
        return False


@admin.register(User)
class UserAdmin(ReadOnlyAccountAdmin):
    search_fields = ("username", "student_id", "real_name")
    list_display = ("username", "student_id", "real_name", "is_active")
    # Hash/salt inspection belongs exclusively to the separately authorized console.
    fieldsets = (
        (None, {"fields": ("username", "email")}),
        ("个人信息", {"fields": ("student_id", "real_name", "school", "identity")}),
        ("权限信息", {"fields": ("is_active", "is_staff", "is_superuser", "permission")}),
        ("认证信息", {"fields": ("email_verified_at", "real_name_verified_at", "advanced_verified_at")}),
        ("重要日期", {"fields": ("last_login", "date_joined")}),
        ("其他信息", {"fields": ("privacy", "quota", "coin", "version")}),
    )


for model in (Quota, Permission, Privacy, TrustedUser, Role, RoleMember, Follow, Notification):
    admin.site.register(model, ReadOnlyAccountAdmin)

if admin.site.is_registered(Group):
    admin.site.unregister(Group)
admin.site.register(Group, ReadOnlyAccountAdmin)
