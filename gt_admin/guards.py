from rest_framework.exceptions import PermissionDenied


def protect_user(actor, target):
    if target.is_privileged and not actor.permission.super_admin:
        raise PermissionDenied("该账号只能由超级管理员通过受保护的管理入口修改")


def protect_role(actor, role):
    for member in role.members.select_related("user__permission"):
        protect_user(actor, member.user)
