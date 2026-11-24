from rest_framework.exceptions import PermissionDenied
from gt_auth.roles import PRIVILEGED_ROLES, assigned_roles, raw_assigned_roles


def reject_global_reader(actor):
    if actor and actor.is_authenticated and "global_reader" in assigned_roles(actor.permission):
        raise PermissionDenied("全局读者仅可读取数据")


def protect_user(actor, target):
    reject_global_reader(actor)
    target_privileged = bool(
        (assigned_roles(target.permission) | raw_assigned_roles(target.permission)) & PRIVILEGED_ROLES
    )
    if target_privileged and "super_admin" not in assigned_roles(actor.permission):
        raise PermissionDenied("该账号只能由超级管理员通过受保护的管理入口修改")


def protect_role(actor, role):
    reject_global_reader(actor)
    for member in role.members.select_related("user__permission"):
        protect_user(actor, member.user)
