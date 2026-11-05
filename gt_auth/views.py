from datetime import datetime, timezone, timedelta
from random import choice
from string import digits
from time import time

from django.db.models import Q
from django.core.mail import send_mail
from django.core.cache import caches, cache
from django.conf import settings
from django.db import transaction
from django.shortcuts import get_object_or_404

from rest_framework import status
from rest_framework.decorators import action
from rest_framework.exceptions import ValidationError, AuthenticationFailed
from rest_framework.mixins import ListModelMixin
from rest_framework.permissions import IsAuthenticated, IsAuthenticatedOrReadOnly
from rest_framework.response import Response
from rest_framework.viewsets import GenericViewSet, ModelViewSet, ReadOnlyModelViewSet

from .models import (
    User,
    Role,
    RoleMember,
    IdentityChoice,
    TrustedUser,
    Quota,
    SourceChoice,
    Permission,
    Privacy,
    Notification,
    Follow,
    SchoolChoice,
)
from .serializers import (
    UserDetailReadSerializer,
    UserBriefSerializer,
    PrivateUserReferenceSerializer,
    QuotaSerializer,
    PermissionSerializer,
    PrivacySerializer,
    RoleBriefSerializer,
    RoleBriefSelfSerializer,
    UserCreateSerializer,
    RoleDetailSerializer,
    RoleFullSerializer,
    RoleSerializer,
    NotificationSerializer,
)
from gt.permissions import Hccaptcha
from gt.parsers import AUTH_PARSERS
from gt.jwt import GtSignature
from gt_coin.models import Coin, CoinRecordType
import gt_coin.amount as coin_amount

def get_authorization(user, remember_me=False):
    from .sessions import authorization
    return authorization(user, getattr(user, "_security_session", None))


def make_user_response(user, login=False, remember_me=False):
    from .security_policy import security_summary
    from .roles import ROLE_LABELS, assigned_roles
    from gt_admin.audit import watermark_id
    session = getattr(user, "_security_session", None)
    roles = Role.objects.filter(members__user=user, deleted=False).order_by("id")
    permissions = {key: User.has_permission(user, key) for key in ROLE_LABELS}
    return Response({
        "msg": "ok", "authorization": get_authorization(user) if login else None,
        "user": UserDetailReadSerializer(user).data, "quota": QuotaSerializer(user.quota).data,
        "permission": permissions, "assigned_roles": sorted(assigned_roles(user.permission)),
        "coin": user.coin.total, "signed": bool(user.coin.record_today.sign),
        "roles": RoleBriefSelfSerializer(roles, many=True, context={"safe": True}).data,
        "captcha_required": settings.HCCAPTCHA_REQUIRED,
        "captcha_expire_time": cache.get(f"captcha_valid:{user.id}") or 0,
        "security": security_summary(user, session), "watermark_id": watermark_id(session),
    })


class UserViewset(ReadOnlyModelViewSet):
    permission_classes = [IsAuthenticated]
    parser_classes = AUTH_PARSERS
    search_fields = ["real_name", "^username"]

    def get_serializer_class(self):
        return UserBriefSerializer

    def get_queryset(self):
        from .privacy import discoverable_users
        queryset = discoverable_users(self.request.user)
        if not User.has_permission(self.request.user, "admin_user"):
            queryset = queryset.exclude(id=self.request.user.id)
        return queryset.order_by("id")

    def get_object(self):
        pk = self.kwargs.get("pk")
        queryset = self.get_queryset()
        if pk.isdigit():
            return get_object_or_404(queryset, id=pk)
        return get_object_or_404(queryset, username=pk)

    @action(detail=False,
            methods=["post"],
            url_path="login",
            permission_classes=[Hccaptcha])
    def login(self, request):
        from .security_views import password_login
        return password_login(request)

    @action(detail=False, methods=["post"], url_path="email_sendcode")
    def email_sendcode(self, request):
        from .education import send_email_code
        from .security_views import require_account_factor
        require_account_factor(request)
        return Response(send_email_code(request.data.get("email"), "bind", request, user=request.user))

    @action(detail=False, methods=["post"], url_path="email_verifycode")
    def email_verifycode(self, request):
        from django.db import IntegrityError, transaction
        from .education import consume_email_code, bind_verified_email
        from .security_views import require_account_factor
        from .sessions import create_session
        require_account_factor(request)
        email = consume_email_code(request.data.get("challenge_id"), request.data.get("code"), "bind", user=request.user)
        user = request.user
        old_session = request.security_session
        try:
            with transaction.atomic():
                bind_verified_email(user, email)
        except IntegrityError:
            raise ValidationError("该邮箱已绑定其他账号")
        create_session(user, old_session.methods, credential=old_session.credential,
                       scope="enrollment" if user.is_management else "full")
        return make_user_response(user, True)

    def create(self, request, *args, **kwargs):
        raise ValidationError("请使用教育邮箱自助注册")

    @action(
        detail=False,
        methods=["get"],
        url_path="info",
        permission_classes=[IsAuthenticated],
    )
    def info(self, request):
        return make_user_response(request.user, True,
                                  request.GET.get("remember_me") == "true")

    @action(
        detail=False,
        methods=["post", "get"],
        url_path="captcha",
        permission_classes=[IsAuthenticated, Hccaptcha],
    )
    def captcha(self, request):
        user = request.user
        captcha_expire_time = cache.get(f"captcha_valid:{user.id}") or 0
        return Response({
            "msg": "ok",
            "captcha_expire_time": captcha_expire_time
        })


class UserSettingViewset(GenericViewSet):
    permission_classes = [IsAuthenticated]
    parser_classes = AUTH_PARSERS

    @action(detail=False, methods=["post"], url_path="password")
    def change_password(self, request):
        user: User = request.user
        old_password = request.data.get("old_password")
        new_password = request.data.get("new_password")
        remember_me = request.data.get("remember_me") == True

        if not isinstance(old_password, str) or len(old_password) > 1024 or not user.check_password(old_password):
            raise ValidationError("原密码错误")
        if not isinstance(new_password, str) or not 1 <= len(new_password) <= 1024:
            raise ValidationError("新密码格式不正确")

        from django.contrib.auth.password_validation import validate_password
        from .security_views import require_account_factor
        from .sessions import create_session
        require_account_factor(request, password=old_password)
        validate_password(new_password, user)
        old_session = request.security_session
        user.set_password(new_password)
        user.version += 1
        user.add_captcha_expire_seconds(1800, update=False)
        user.save()

        create_session(user, old_session.methods, credential=old_session.credential,
                       remember=remember_me, scope=old_session.scope)
        return make_user_response(user, True, remember_me)

    @action(detail=False, methods=["get", "put"], url_path="privacy")
    def privacy(self, request):
        user = request.user
        trusted_users = User.objects.filter(trusted_by_users__user=user)
        if request.method == "PUT":
            serializer = PrivacySerializer(user.privacy,
                                           data=request.data,
                                           partial=True, context={"request": request})
            serializer.is_valid(raise_exception=True)
            serializer.save()

            new_trusted_users = serializer.validated_data.get("trusted_users")

            if new_trusted_users is not None:
                old_trusted_users = user.trusted_users.values_list(
                    "trusted_user_id", flat=True)
                to_add, to_remove = [], []
                for new_trusted_user in new_trusted_users:
                    if new_trusted_user not in old_trusted_users:
                        to_add.append(new_trusted_user)
                for old_trusted_user in old_trusted_users:
                    if old_trusted_user not in new_trusted_users:
                        to_remove.append(old_trusted_user)
                TrustedUser.objects.filter(
                    user=user, trusted_user_id__in=to_remove).delete()
                for trusted_user_id in to_add:
                    TrustedUser.objects.create(user=user,
                                               trusted_user_id=trusted_user_id)

        return Response({
            "msg":
            "ok",
            "privacy":
            PrivacySerializer(user.privacy).data,
            "trusted_users":
            PrivateUserReferenceSerializer(trusted_users, many=True, context={"request": request}).data,
        })


class RoleViewset(ModelViewSet):
    permission_classes = [IsAuthenticatedOrReadOnly]
    serializer_class = RoleBriefSerializer
    search_fields = ["name"]
    filterset_fields = [
        "followers__follower",
        "followings__following",
    ]

    def get_queryset(self):
        _queryset = Role.objects.exclude(is_private=True).exclude(deleted=True)
        queryset_my = Role.objects.none()
        if self.request.user.is_authenticated:
            queryset_my = Role.objects.filter(members__user=self.request.user)
        queryset = (_queryset | queryset_my).exclude(deleted=True).distinct()
        return queryset.order_by("id")

    def retrieve(self, request, *args, **kwargs):
        instance = self.get_object()
        if (request.user.is_authenticated
                and instance.members.filter(user=request.user).exists()):
            serializer = RoleFullSerializer(
                instance, context=self.get_serializer_context())
        else:
            serializer = RoleDetailSerializer(
                instance, context=self.get_serializer_context())
        return Response({"msg": "ok", "data": serializer.data})

    def check_editable(self, request):
        role = self.get_object()
        if not role.editable:
            raise ValidationError("当前角色不允许编辑")
        elif not RoleMember.objects.filter(
                user=request.user, role=role, is_owner=True).exists():
            raise ValidationError("仅所有者可编辑角色")

    @transaction.atomic
    def update(self, request, *args, **kwargs):
        role = Role.objects.select_for_update().get(pk=self.get_object().pk)
        self.check_editable(request)

        serializer = RoleFullSerializer(role,
                                        data=request.data,
                                        partial=True,
                                        context={"user": request.user})
        serializer.is_valid(raise_exception=True)
        serializer.save()

        new_members = serializer.validated_data.get("members_id")

        if new_members is not None:
            old_members = role.members.values_list("user_id", flat=True)
            to_add, to_remove = [], []
            for new_member in new_members:
                if new_member not in old_members:
                    to_add.append(new_member)
            for old_member in old_members:
                if old_member not in new_members:
                    to_remove.append(old_member)
            RoleMember.objects.filter(role=role,
                                      is_owner=False,
                                      user_id__in=to_remove).delete()
            for user_id in to_add:
                RoleMember.objects.create(role=role, user_id=user_id)

        if getattr(role, "_prefetched_objects_cache", None):
            role._prefetched_objects_cache = {}

        return Response({"msg": "ok", "data": serializer.data})

    @transaction.atomic
    def create(self, request, *args, **kwargs):
        user = request.user
        if user.roles.count() >= user.quota.role_count_limit:
            raise ValidationError(f"你的角色数超过限制{user.quota.role_count_limit}")
        serializer = RoleFullSerializer(data=request.data,
                                        context={"user": user})
        serializer.is_valid(raise_exception=True)
        serializer.save()

        RoleMember.objects.create(user=user,
                                  role=serializer.instance,
                                  is_owner=True)
        RoleMember.objects.bulk_create([
            RoleMember(user_id=user_id, role=serializer.instance)
            for user_id in serializer.validated_data.get("members_id", []) if user_id != user.pk
        ])

        user.add_captcha_expire_seconds(600)

        return Response(
            {
                "msg": "ok",
                "data": RoleBriefSerializer(serializer.instance).data,
            },
            status=status.HTTP_201_CREATED,
        )

    def perform_destroy(self, instance):
        self.check_editable(self.request)
        if instance.is_primary:
            raise ValidationError("注册主角色不能删除，可以修改名称或实名展示设置")
        instance.deleted = True
        instance.save(update_fields=["deleted"])

    @action(
        detail=True,
        methods=["post"],
        url_path="follow",
        permission_classes=[IsAuthenticated],
    )
    def follow(self, request, pk):
        role = request.role
        instance = self.get_object()
        follow_item, created = Follow.objects.get_or_create(follower=role,
                                                            following=instance)
        if not created:
            follow_item.delete()
            instance.follower_count -= 1
            instance.save(update_fields=["follower_count"])
            role.following_count -= 1
            role.save(update_fields=["following_count"])
        else:
            instance.follower_count += 1
            instance.save(update_fields=["follower_count"])
            role.following_count += 1
            role.save(update_fields=["following_count"])
        return Response({
            "msg": "ok",
            "followed": created,
            "follower_count": instance.follower_count,
        })


class NotificationViewset(GenericViewSet, ListModelMixin):
    permission_classes = [IsAuthenticated]
    serializer_class = NotificationSerializer
    filterset_fields = ["is_read"]

    def get_queryset(self):
        return Notification.objects.filter(
            role=self.request.role).order_by("-id")

    def list(self, request, *args, **kwargs):
        response = super().list(request, *args, **kwargs)
        unread_count = self.get_queryset().filter(is_read=False).count()
        response.data.update({"unread_count": unread_count})
        return response

    def delete(self, request, *args, **kwargs):
        self.get_queryset().delete()
        return Response({"msg": "ok"})

    @action(methods=["post"], detail=False, url_path="read_all")
    def read_all(self, request):
        self.get_queryset().update(is_read=True)
        return Response({"msg": "ok"})

    @action(methods=["post"], detail=True, url_path="read")
    def read(self, request, pk):
        instance = self.get_object()
        instance.is_read = True
        instance.save(update_fields=["is_read"])
        return Response({"msg": "ok"})
