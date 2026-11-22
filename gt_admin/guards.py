from rest_framework.exceptions import PermissionDenied
from gt_auth.roles import assigned_roles


def protect_user(actor, target):
    if target.is_privileged and "super_admin" not in assigned_roles(actor.permission):
        raise PermissionDenied("该账号只能由超级管理员通过受保护的管理入口修改")


def protect_role(actor, role):
    for member in role.members.select_related("user__permission"):
        protect_user(actor, member.user)
