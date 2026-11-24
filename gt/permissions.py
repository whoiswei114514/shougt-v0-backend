from time import time

from django.core.cache import cache
from django.conf import settings
from requests import post
from rest_framework import permissions


class Hccaptcha(permissions.BasePermission):

    def has_permission(self, request, view):
        if not settings.HCCAPTCHA_REQUIRED:
            return True
        if request.method in ["GET", "HEAD", "OPTIONS"]:
            return True
        user = request.user
        if user.is_authenticated and cache.get(f"captcha_valid:{user.id}"):
            return True
        token = request.data.get("captcha_token") if isinstance(request.data, dict) else None
        if not token:
            return False
        response = post(
            settings.HCCAPTCHA_CHECK_URL,
            data={"request_id": token},
            timeout=10,
        ).json()
        flag = response["status"] == "success"
        if flag and user.is_authenticated:
            cache.set(
                f"captcha_valid:{user.id}",
                int(time()) + user.captcha_expire_seconds - 1,
                timeout=user.captcha_expire_seconds,
            )
        return flag


class IsServer(permissions.BasePermission):

    def has_permission(self, request, view):
        return request.is_server


class IsAdminOrReadCreate(permissions.BasePermission):

    def has_permission(self, request, view):
        if request.method in ["GET", "HEAD", "OPTIONS", "POST"]:
            return True
        from gt_auth.models import User
        return User.has_permission(request.user, "super_admin")


class HaveRoleOrReadOnly(permissions.BasePermission):

    def has_permission(self, request, view):
        if request.method in ["GET", "HEAD", "OPTIONS"]:
            return True
        role = getattr(request, "role", None)
        return bool(
            request.user
            and request.user.is_authenticated
            and getattr(request.user, "is_currently_active", True)
            and role is not None
            and not getattr(role, "deleted", False)
            and getattr(role, "is_currently_active", True)
        )


def HasPermission(permission: str):

    class _HasPermission(permissions.BasePermission):

        def has_permission(self, request, view):
            if not hasattr(request, "user"):
                return False
            if not hasattr(request.user, "permission"):
                return False
            from gt_auth.models import User
            from gt_auth.roles import assigned_roles
            if (request.method not in permissions.SAFE_METHODS and
                    request.user.is_authenticated and
                    "global_reader" in assigned_roles(request.user.permission)):
                return False
            return User.has_permission(request.user, permission)

    return _HasPermission


def HasPermissionOrReadOnly(permission: str):

    class _HasPermissionOrReadOnly(HasPermission(permission)):

        def has_permission(self, request, view):
            if request.method in ["GET", "HEAD", "OPTIONS"]:
                return True
            return super().has_permission(request, view)

    return _HasPermissionOrReadOnly
