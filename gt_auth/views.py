from datetime import date, datetime, timezone, timedelta
from random import choice
from string import digits
from time import time

from django.db.models import Count, F, Q
from django.core.mail import send_mail
from django.core.cache import caches, cache
from django.conf import settings
from django.db import transaction
from django.shortcuts import get_object_or_404
from django_filters import rest_framework as filters

from rest_framework import status
from rest_framework.decorators import action
from rest_framework.exceptions import ValidationError, AuthenticationFailed, PermissionDenied
from rest_framework.filters import OrderingFilter, SearchFilter
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
from gt.permissions import HaveRoleOrReadOnly, Hccaptcha
from gt.parsers import AUTH_PARSERS
from gt.jwt import GtSignature
from gt_coin.models import Coin, CoinRecord, CoinRecordType
from .privacy import visible_roles
from .roles import assigned_roles
import gt_coin.amount as coin_amount

def get_authorization(user, remember_me=False):
    from .sessions import authorization
    return authorization(user, getattr(user, "_security_session", None))


def _reject_global_reader(user):
    if user and user.is_authenticated and "global_reader" in assigned_roles(user.permission):
        raise PermissionDenied("全局读者仅可读取数据")


def _reject_impersonation(request, message="代登录会话不能执行此账号操作"):
    session = getattr(request, "security_session", None) or getattr(request.user, "_security_session", None)
    if session and session.scope == "impersonation":
        raise PermissionDenied(message)


def make_user_response(user, login=False, remember_me=False):
    from .security_policy import security_summary
    from .roles import ROLE_LABELS, assigned_roles
    from gt_admin.audit import watermark_id
    session = getattr(user, "_security_session", None)
    roles = (
        Role.objects.filter(members__user=user, deleted=False)
        .annotate(_unread_count=Count("notifications", filter=Q(notifications__is_read=False)))
        .order_by("id")
    )
    permissions = {key: User.has_permission(user, key) for key in ROLE_LABELS}
    today_record = CoinRecord.objects.filter(user=user, date=date.today()).first()
    return Response({
        "msg": "ok", "authorization": get_authorization(user) if login else None,
        "user": UserDetailReadSerializer(user).data, "quota": QuotaSerializer(user.quota).data,
        "permission": permissions, "assigned_roles": sorted(assigned_roles(user.permission)),
        "coin": user.coin.total, "signed": bool(today_record and today_record.sign),
        "roles": RoleBriefSelfSerializer(roles, many=True, context={"safe": True}).data,
        "captcha_required": settings.HCCAPTCHA_REQUIRED,
        "captcha_expire_time": cache.get(f"captcha_valid:{user.id}") or 0,
        "security": security_summary(user, session), "watermark_id": watermark_id(session),
    })


class UserViewset(ReadOnlyModelViewSet):
    permission_classes = [IsAuthenticated]
    parser_classes = AUTH_PARSERS
    filter_backends = [OrderingFilter, SearchFilter]
    ordering_fields = ["id", "username", "real_name"]
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
        from .security_policy import enrollment_complete
        from .security_views import require_account_factor
        from .sessions import create_session
        _reject_global_reader(request.user)
        require_account_factor(request)
        email = consume_email_code(request.data.get("challenge_id"), request.data.get("code"), "bind", user=request.user)
        user = request.user
        old_session = request.security_session
        try:
            with transaction.atomic():
                bind_verified_email(user, email)
        except IntegrityError:
            raise ValidationError("该邮箱已绑定其他账号")
        scope = "enrollment" if user.is_management and (user.admin_onboarding_required or not enrollment_complete(user)) else "full"
        create_session(user, old_session.methods, credential=old_session.credential,
                       second_credential=old_session.second_credential, scope=scope)
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
    filter_backends = []

    @action(detail=False, methods=["post"], url_path="password")
    def change_password(self, request):
        user: User = request.user
        _reject_global_reader(user)
        old_password = request.data.get("old_password")
        new_password = request.data.get("new_password")
        remember_me = request.data.get("remember_me") == True

        if not isinstance(old_password, str) or len(old_password) > 1024 or not user.check_password(old_password):
            raise ValidationError("原密码错误")
        if not isinstance(new_password, str) or not 1 <= len(new_password) <= 1024:
            raise ValidationError("新密码格式不正确")

        from django.contrib.auth.password_validation import validate_password
        from .security_policy import enrollment_complete
        from .security_views import require_account_factor
        from .sessions import create_session
        require_account_factor(request, password=old_password)
        validate_password(new_password, user)
        old_session = request.security_session
        user.set_password(new_password)
        user.version += 1
        user.add_captcha_expire_seconds(1800, update=False)
        user.save()

        scope = "enrollment" if user.is_management and (user.admin_onboarding_required or not enrollment_complete(user)) else old_session.scope
        create_session(user, old_session.methods, credential=old_session.credential,
                       second_credential=old_session.second_credential,
                       remember=remember_me, scope=scope)
        return make_user_response(user, True, remember_me)

    @action(detail=False, methods=["get", "put"], url_path="privacy")
    def privacy(self, request):
        user = request.user
        if request.method == "PUT":
            _reject_global_reader(user)
            _reject_impersonation(request, "代登录会话不能修改账号隐私设置")
            with transaction.atomic():
                serializer = PrivacySerializer(user.privacy,
                                               data=request.data,
                                               partial=True, context={"request": request})
                serializer.is_valid(raise_exception=True)
                serializer.save()

                new_trusted_users = serializer.validated_data.get("trusted_users")

                if new_trusted_users is not None:
                    old_trusted_users = set(user.trusted_users.values_list(
                        "trusted_user_id", flat=True))
                    to_add = [uid for uid in new_trusted_users if uid not in old_trusted_users]
                    to_remove = [uid for uid in old_trusted_users if uid not in new_trusted_users]
                    TrustedUser.objects.filter(
                        user=user, trusted_user_id__in=to_remove).delete()
                    for trusted_user_id in to_add:
                        TrustedUser.objects.create(user=user,
                                                   trusted_user_id=trusted_user_id)

        trusted_users = User.objects.filter(trusted_by_users__user=user)
        return Response({
            "msg":
            "ok",
            "privacy":
            PrivacySerializer(user.privacy).data,
            "trusted_users":
            PrivateUserReferenceSerializer(trusted_users, many=True, context={"request": request}).data,
        })


class RoleFilter(filters.FilterSet):
    followers__follower = filters.NumberFilter(method="filter_visible_relation")
    followings__following = filters.NumberFilter(method="filter_visible_relation")

    def filter_visible_relation(self, queryset, name, value):
        if not visible_roles(self.request.user).filter(pk=value).exists():
            return queryset.none()
        return queryset.filter(**{name: value})

    class Meta:
        model = Role
        fields = []


class RoleViewset(ModelViewSet):
    permission_classes = [IsAuthenticatedOrReadOnly]
    serializer_class = RoleBriefSerializer
    filter_backends = [filters.DjangoFilterBackend, OrderingFilter, SearchFilter]
    search_fields = ["name"]
    ordering_fields = ["id", "name", "following_count", "follower_count"]
    filterset_class = RoleFilter

    def get_queryset(self):
        return visible_roles(self.request.user).order_by("id")

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

    def check_editable(self, request, role=None, *, allow_role_admin=False):
        role = role or self.get_object()
        if not role.editable:
            raise ValidationError("当前角色不允许编辑")
        if not role.is_currently_active:
            raise ValidationError("当前角色已被封禁，不能编辑")
        if role.is_owner(request.user):
            return True
        if allow_role_admin and role.is_shared and role.is_role_admin(request.user):
            return False
        if allow_role_admin:
            raise ValidationError("仅角色所有者或角色管理员可管理角色成员")
        raise ValidationError("仅所有者可编辑角色")

    @transaction.atomic
    def update(self, request, *args, **kwargs):
        _reject_global_reader(request.user)
        _reject_impersonation(request, "代登录会话不能修改角色")
        if not isinstance(request.data, dict):
            raise ValidationError("请求参数格式错误")
        role = Role.objects.select_for_update().get(pk=self.get_object().pk)
        is_owner = self.check_editable(request, role=role, allow_role_admin=True)
        if not is_owner:
            allowed_keys = {"id", "members_id"}
            extra_keys = set(request.data.keys()) - allowed_keys
            if extra_keys or "members_id" not in request.data:
                raise PermissionDenied("角色管理员仅可添加或移除共享角色成员")
            if "id" in request.data and request.data.get("id") != role.pk:
                raise PermissionDenied("角色管理员不能修改角色基本信息")
            serializer = RoleFullSerializer(
                role,
                data={"members_id": request.data.get("members_id")},
                partial=True,
                context={"user": request.user, "request": request, "member_only_update": True},
            )
            serializer.is_valid(raise_exception=True)
            new_members = serializer.validated_data["members_id"]
            admin_ids = set(
                role.members.filter(is_owner=False, is_admin=True).values_list("user_id", flat=True)
            )
            if admin_ids - set(new_members):
                raise ValidationError("角色管理员不能移除其他角色管理员")
            old_members = set(role.members.filter(is_owner=False).values_list("user_id", flat=True))
            owner = role.owner
            owner_id = owner.pk if owner else None
            to_add = [uid for uid in new_members if uid not in old_members and uid != owner_id]
            to_remove = [uid for uid in old_members if uid not in new_members]
            RoleMember.objects.filter(role=role, is_owner=False, is_admin=False, user_id__in=to_remove).delete()
            for user_id in to_add:
                RoleMember.objects.create(role=role, user_id=user_id)
            if getattr(role, "_prefetched_objects_cache", None):
                role._prefetched_objects_cache = {}
            return Response({"msg": "ok", "data": serializer.data})

        serializer = RoleFullSerializer(
            role,
            data=request.data,
            partial=True,
            context={"user": request.user, "request": request},
        )
        serializer.is_valid(raise_exception=True)
        serializer.save()

        if not role.is_shared:
            RoleMember.objects.filter(role=role, is_owner=False).delete()
        else:
            new_members = serializer.validated_data.get("members_id")
            new_admins = serializer.validated_data.get("admins_id")
            if new_members is not None:
                old_members = set(role.members.filter(is_owner=False).values_list("user_id", flat=True))
                owner = role.owner
                owner_id = owner.pk if owner else None
                to_add = [uid for uid in new_members if uid not in old_members and uid != owner_id]
                to_remove = [uid for uid in old_members if uid not in new_members]
                RoleMember.objects.filter(role=role, is_owner=False, user_id__in=to_remove).delete()
                for user_id in to_add:
                    RoleMember.objects.create(role=role, user_id=user_id)
            if new_admins is not None:
                admin_set = set(new_admins)
                RoleMember.objects.filter(role=role, is_owner=False).exclude(user_id__in=admin_set).update(is_admin=False)
                RoleMember.objects.filter(role=role, is_owner=False, user_id__in=admin_set).update(is_admin=True)

        if getattr(role, "_prefetched_objects_cache", None):
            role._prefetched_objects_cache = {}

        return Response({"msg": "ok", "data": serializer.data})

    @transaction.atomic
    def create(self, request, *args, **kwargs):
        _reject_global_reader(request.user)
        _reject_impersonation(request, "代登录会话不能创建角色")
        user = User.objects.select_for_update().get(pk=request.user.pk)
        if user.roles.count() >= user.quota.role_count_limit:
            raise ValidationError(f"你的角色数超过限制{user.quota.role_count_limit}")
        serializer = RoleFullSerializer(data=request.data,
                                        context={"user": user, "request": request})
        serializer.is_valid(raise_exception=True)
        serializer.save()

        RoleMember.objects.create(user=user,
                                  role=serializer.instance,
                                  is_owner=True)
        admins_set = set(serializer.validated_data.get("admins_id", []))
        RoleMember.objects.bulk_create([
            RoleMember(user_id=user_id, role=serializer.instance, is_admin=(user_id in admins_set))
            for user_id in serializer.validated_data.get("members_id", []) if user_id != user.pk
        ])

        user.add_captcha_expire_seconds(600)

        return Response(
            {
                "msg": "ok",
                "data": RoleBriefSerializer(serializer.instance, context={"request": request, "safe": True}).data,
            },
            status=status.HTTP_201_CREATED,
        )

    def perform_destroy(self, instance):
        _reject_global_reader(self.request.user)
        _reject_impersonation(self.request, "代登录会话不能删除角色")
        self.check_editable(self.request)
        if instance.is_primary:
            raise ValidationError("注册主角色不能删除，可以修改名称或实名展示设置")
        instance.deleted = True
        instance.save(update_fields=["deleted"])

    @action(
        detail=True,
        methods=["post"],
        url_path="follow",
        permission_classes=[IsAuthenticated, HaveRoleOrReadOnly],
    )
    @transaction.atomic
    def follow(self, request, pk):
        _reject_global_reader(request.user)
        role = request.role
        if role is None:
            raise ValidationError("请先选择当前角色")
        instance = Role.objects.select_for_update().get(pk=self.get_object().pk)
        if instance.is_private or not instance.is_currently_active:
            raise ValidationError("当前角色不可关注")
        role = Role.objects.select_for_update().get(pk=role.pk)
        follow_item, created = Follow.objects.get_or_create(follower=role,
                                                            following=instance)
        if not created:
            follow_item.delete()
            Role.objects.filter(pk=instance.pk).update(follower_count=F("follower_count") - 1)
            Role.objects.filter(pk=role.pk).update(following_count=F("following_count") - 1)
        else:
            Role.objects.filter(pk=instance.pk).update(follower_count=F("follower_count") + 1)
            Role.objects.filter(pk=role.pk).update(following_count=F("following_count") + 1)
        instance.refresh_from_db(fields=["follower_count"])
        return Response({
            "msg": "ok",
            "followed": created,
            "follower_count": instance.follower_count,
        })


class NotificationViewset(GenericViewSet, ListModelMixin):
    permission_classes = [IsAuthenticated]
    serializer_class = NotificationSerializer
    filter_backends = [filters.DjangoFilterBackend, OrderingFilter]
    filterset_fields = ["is_read"]
    ordering_fields = ["id", "time", "is_read"]

    def get_queryset(self):
        if self.request.role is None:
            return Notification.objects.none()
        return Notification.objects.filter(
            role=self.request.role).order_by("-id")

    def list(self, request, *args, **kwargs):
        response = super().list(request, *args, **kwargs)
        unread_count = self.get_queryset().filter(is_read=False).count()
        response.data.update({"unread_count": unread_count})
        return response

    def delete(self, request, *args, **kwargs):
        _reject_global_reader(request.user)
        self.get_queryset().delete()
        return Response({"msg": "ok"})

    @action(methods=["post"], detail=False, url_path="read_all")
    def read_all(self, request):
        _reject_global_reader(request.user)
        self.get_queryset().update(is_read=True)
        return Response({"msg": "ok"})

    @action(methods=["post"], detail=True, url_path="read")
    def read(self, request, pk):
        _reject_global_reader(request.user)
        instance = self.get_object()
        instance.is_read = True
        instance.save(update_fields=["is_read"])
        return Response({"msg": "ok"})
