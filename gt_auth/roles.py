"""Persist explicit grants; derive role inheritance at the boundary."""
ROLE_LABELS = {
    "base_admin": "实习管理员", "admin_user": "用户管理员",
    "admin_role": "角色管理员", "admin_alumni": "校友墙维护",
    "no_review": "老学究", "admin_file": "文件仓管", "admin_image": "图片小编",
    "admin_report": "闰土", "admin_forum": "藤野先生", "super_admin": "超级管理员",
    "admin_admin": "特权管理员", "superadmin_admin": "特权超级管理员",
}
PRIVILEGED_ROLES = frozenset({"super_admin", "admin_admin", "superadmin_admin"})
EXCLUSIVE_ROLES = frozenset({"admin_admin", "superadmin_admin"})
MANAGEMENT_ROLES = frozenset(ROLE_LABELS) - {"no_review"}
ORDINARY_ROLES = MANAGEMENT_ROLES - PRIVILEGED_ROLES


def assigned_roles(permission):
    return {name for name in ROLE_LABELS if getattr(permission, name, False)}


def effective_roles(permission):
    roles = assigned_roles(permission)
    if "super_admin" in roles:
        roles |= ORDINARY_ROLES | {"no_review"}
    if "admin_user" in roles:
        roles.add("admin_role")
    if roles & MANAGEMENT_ROLES:
        roles.add("base_admin")
    return roles


def validate_roles(roles):
    roles = set(roles)
    if roles - ROLE_LABELS.keys():
        raise ValueError("包含未知管理角色")
    for exclusive in EXCLUSIVE_ROLES:
        if exclusive in roles and roles - {exclusive, "no_review"}:
            raise ValueError("特权管理角色只能与老学究同时持有")
    return roles


def visible_badges(permission):
    roles = effective_roles(permission)
    if "super_admin" in roles:
        roles = {"super_admin"}
    else:
        if roles & (MANAGEMENT_ROLES - {"base_admin"}):
            roles.discard("base_admin")
        if "admin_user" in roles:
            roles.discard("admin_role")
    return [{"role": key, "label": label} for key, label in ROLE_LABELS.items() if key in roles]


def may_assign(actor_roles, target_roles, desired_roles, *, is_self=False):
    actor, target, desired = map(set, (actor_roles, target_roles, desired_roles))
    validate_roles(desired)
    if is_self:
        raise ValueError("不能修改自己的管理角色")
    if "super_admin" in actor or "superadmin_admin" in actor:
        # The latter is the explicit exception in the privileged-super-admin requirement.
        return True
    if "admin_admin" in actor:
        if (target | desired) & PRIVILEGED_ROLES:
            raise ValueError("特权管理员不能指派或修改超级管理员及特权管理角色")
        return True
    raise ValueError("管理角色只能在特权管理页面指派")
