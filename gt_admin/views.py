import re
from django.core.exceptions import PermissionDenied
from django.shortcuts import get_object_or_404
from django.utils import timezone
from django.db import transaction
from django.db.models import Case, IntegerField, Q, Value, When
from django.contrib.auth.password_validation import validate_password
from django_filters.rest_framework import DjangoFilterBackend
from rest_framework.decorators import action
from rest_framework.exceptions import ValidationError
from rest_framework.filters import OrderingFilter, SearchFilter
from rest_framework.permissions import BasePermission, IsAuthenticated
from rest_framework.response import Response
from rest_framework.viewsets import GenericViewSet, ModelViewSet
from rest_framework.mixins import UpdateModelMixin, ListModelMixin, RetrieveModelMixin
from gt.permissions import HasPermission, HasPermissionOrReadOnly
from .models import Report, ReportStatusChoice, ReportContentTypeChoice
from .guards import protect_user, protect_role, reject_global_reader
from .audit import record
from .serializers import (
    ReportCreateSerializer,
    ReportSerializer,
    ReviewSerializer,
    AddCoinRecordSerializer,
)
from gt_auth.models import Role, User, resolve_ban_state
from gt_auth.roles import ROLE_LABELS, assigned_roles
from gt_auth.privacy import discoverable_users, visible_roles
from gt_auth.serializers import (
    PermissionSerializer,
    QuotaSerializer,
    RoleAdminSerializer,
    RoleFullSerializer,
    UserDetailReadSerializer,
)
from gt_forum.models import Post, PostComment, PostVersion
from gt_forum.visibility import visible_posts, visible_comments
from gt_forum.serializers import (
    PostFullSerializer,
    PostListSerializer,
    PostCommentAdminSerializer,
    PostVersionListSerializer,
    PostVersionSerializer,
)


class ReportPermission(BasePermission):

    def has_permission(self, request, view):
        if view.action in ["retrieve", "list"]:
            return True
        if request.user and request.user.is_authenticated and "global_reader" in assigned_roles(request.user.permission):
            return False
        if view.action == "create":
            return True
        return User.has_permission(request.user, "admin_report")


class ReportViewset(ModelViewSet):
    permission_classes = [IsAuthenticated, ReportPermission]
    filter_backends = [DjangoFilterBackend, OrderingFilter]
    filterset_fields = ["status"]
    ordering_fields = ["id", "status", "create_time", "operate_time"]

    def get_queryset(self):
        queryset = Report.objects.all()
        if not User.has_permission(self.request.user, "admin_report"):
            queryset = queryset.filter(user=self.request.user)
        return queryset.order_by("-id")

    def get_serializer_class(self):
        if self.action == "create":
            return ReportCreateSerializer
        return ReportSerializer

    def create(self, request, *args, **kwargs):
        user = request.user
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        content_type = serializer.validated_data["content_type"]
        reportable = {
            ReportContentTypeChoice.POST: visible_posts(user, request.role),
            ReportContentTypeChoice.COMMENT: visible_comments(user, request.role).filter(deleted=False),
            ReportContentTypeChoice.ROLE: visible_roles(user),
            ReportContentTypeChoice.USER: discoverable_users(user),
        }
        target = get_object_or_404(reportable[content_type], pk=serializer.validated_data["content_id"])
        if Report.objects.filter(
            user=user,
            content_type=serializer.validated_data["content_type"],
            content_id=serializer.validated_data["content_id"],
            status=ReportStatusChoice.PENDING,
        ).exists():
            raise ValidationError("你已经举报过该内容")
        extra_content = {"post_type": target.type} if content_type == ReportContentTypeChoice.POST else None
        serializer.save(user=user, extra_content=extra_content)
        return Response({"msg": "ok"})

    def perform_update(self, serializer):
        serializer.save(operator=self.request.user, operate_time=timezone.now())


class UserIdSearchFilter(SearchFilter):
    id_field = "id"

    def filter_queryset(self, request, queryset, view):
        params = getattr(request, "query_params", request.GET)
        raw = params.get(self.search_param, "").strip()
        match = re.fullmatch(r"(#?)(\d+)", raw)
        if match and len(match.group(2)) <= 18:
            exact_id = int(match.group(2))
            if exact_id >= 1:
                if match.group(1):
                    return queryset.filter(**{self.id_field: exact_id})
                text_matches = super().filter_queryset(request, queryset, view)
                combined = queryset.filter(Q(**{self.id_field: exact_id}) | Q(pk__in=text_matches.values("pk")))
                order_by = queryset.query.order_by or ("id",)
                return combined.annotate(
                    _exact_id_rank=Case(
                        When(**{self.id_field: exact_id}, then=Value(0)),
                        default=Value(1),
                        output_field=IntegerField(),
                    )
                ).order_by("_exact_id_rank", *order_by)
        return super().filter_queryset(request, queryset, view)


class UserAdminViewset(GenericViewSet, UpdateModelMixin, ListModelMixin):
    queryset = User.objects.order_by("id")
    permission_classes = [HasPermission("admin_user")]
    serializer_class = UserDetailReadSerializer
    filter_backends = [DjangoFilterBackend, OrderingFilter, UserIdSearchFilter]
    search_fields = ["real_name", "^username", "^student_id"]
    ordering_fields = ["id", "username", "real_name", "student_id", "date_joined", "is_active", "banned_until"]

    def create(self, request, *args, **kwargs):
        reject_global_reader(request.user)
        from .user_creation import create_user
        return Response(create_user(request), status=201)

    def retrieve(self, request, *args, **kwargs):
        target = self.get_object()
        permissions = {key: User.has_permission(target, key) for key in ROLE_LABELS}
        return Response({
            "msg": "ok",
            "authorization": None,
            "user": UserDetailReadSerializer(target).data,
            "quota": QuotaSerializer(target.quota).data,
            "permission": permissions,
            "assigned_roles": sorted(assigned_roles(target.permission)),
            "coin": target.coin.total,
            "security": {
                "is_management": target.is_management,
                "is_privileged": target.is_privileged,
            },
        })

    def _update(self, instance, serializer_class):
        serializer = serializer_class(instance, data=self.request.data, partial=True)
        serializer.is_valid(raise_exception=True)
        self.perform_update(serializer)
        if getattr(instance, "_prefetched_objects_cache", None):
            instance._prefetched_objects_cache = {}
        return serializer

    def update(self, request, *args, **kwargs):
        user = self.get_object()
        protect_user(request.user, user)
        data_type = request.GET.get("type")
        if data_type == "permission":
            if set(request.data) != {"no_review"} or type(request.data.get("no_review")) is not bool:
                raise ValidationError("此页面仅可设置老学究；其他管理角色请使用独立特权管理站")
            serializer = self._update(user.permission, PermissionSerializer)
        elif data_type == "quota":
            serializer = self._update(user.quota, QuotaSerializer)
        else:
            raise ValidationError("用户基础信息请在独立特权管理站修改")
        return Response({"msg": "ok", "data": serializer.data})

    @action(detail=True, methods=["post"], url_path="change-password")
    def change_password(self, request, pk):
        user: User = self.get_object()
        protect_user(request.user, user)
        if user.is_management and "super_admin" not in assigned_roles(request.user.permission):
            raise PermissionDenied("只有超级管理员可重置管理账号密码")
        password = request.data.get("password")
        if not isinstance(password, str) or not 1 <= len(password) <= 1024:
            raise ValidationError("密码格式不正确")
        validate_password(password, user)
        user.set_password(password)
        user.version += 1
        user.save()
        return Response({"msg": "ok"})

    @action(detail=True, methods=["post"], url_path="coin")
    def coin(self, request, pk):
        serializer = AddCoinRecordSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user: User = self.get_object()
        protect_user(request.user, user)
        user.coin.add_record(
            serializer.validated_data["change"],
            serializer.validated_data["type"],
            f"管理员{request.user.id}操作：{serializer.validated_data.get('detail', '')}",
            allow_negative=True,
        )
        return Response({"msg": "ok"})

    @action(detail=True, methods=["post"], url_path="ban")
    def ban(self, request, pk):
        user: User = self.get_object()
        protect_user(request.user, user)
        if user.pk == request.user.pk:
            raise ValidationError("不能封禁自己")
        is_active, banned_until = resolve_ban_state(request.data)
        user.is_active = is_active
        user.banned_until = banned_until
        user.version += 1
        user.save()
        record(
            request.user,
            "ban_user" if not user.is_currently_active else "unban_user",
            object_type="user",
            object_id=user.pk,
            details={"is_active": is_active, "banned_until": banned_until.isoformat() if banned_until else None},
            session=getattr(request, "security_session", None),
        )
        return Response({
            "msg": "ok",
            "is_active": user.is_currently_active,
            "permanently_banned": not user.is_active,
            "banned_until": user.active_banned_until,
        })


class RoleAdminViewset(
    GenericViewSet, ListModelMixin, RetrieveModelMixin, UpdateModelMixin
):
    queryset = Role.objects.order_by("id")
    permission_classes = [HasPermission("admin_role")]
    filter_backends = [DjangoFilterBackend, OrderingFilter, SearchFilter]
    search_fields = ["id", "name"]
    ordering_fields = ["id", "name", "is_active", "banned_until", "following_count", "follower_count"]

    def perform_update(self, serializer):
        role = serializer.instance
        protect_role(self.request.user, role)
        prev_active, prev_until = role.is_active, role.banned_until
        serializer.save()
        if role.is_active != prev_active or role.banned_until != prev_until:
            record(
                self.request.user,
                "ban_role" if not role.is_currently_active else "unban_role",
                object_type="role",
                object_id=role.pk,
                details={"is_active": role.is_active, "banned_until": role.banned_until.isoformat() if role.banned_until else None},
                session=getattr(self.request, "security_session", None),
            )

    def get_serializer_class(self):
        if self.action == "retrieve":
            return RoleFullSerializer
        return RoleAdminSerializer

    @action(detail=True, methods=["post"], url_path="ban")
    def ban(self, request, pk):
        role: Role = self.get_object()
        protect_role(self.request.user, role)
        is_active, banned_until = resolve_ban_state(request.data)
        role.is_active = is_active
        role.banned_until = banned_until
        role.save(update_fields=["is_active", "banned_until"])
        record(
            request.user,
            "ban_role" if not role.is_currently_active else "unban_role",
            object_type="role",
            object_id=role.pk,
            details={"is_active": is_active, "banned_until": banned_until.isoformat() if banned_until else None},
            session=getattr(request, "security_session", None),
        )
        return Response({
            "msg": "ok",
            "is_active": role.is_currently_active,
            "permanently_banned": not role.is_active,
            "banned_until": role.active_banned_until,
        })


class PostAdminViewset(GenericViewSet, ListModelMixin, RetrieveModelMixin):
    permission_classes = [IsAuthenticated, HasPermissionOrReadOnly("admin_forum")]
    filter_backends = [DjangoFilterBackend, OrderingFilter, SearchFilter]
    search_fields = ["id", "title", "content"]
    ordering_fields = ["id", "create_time", "edit_time", "update_time", "like_count", "comment_count", "review_status", "pinned"]

    def get_queryset(self):
        queryset = Post.objects.order_by("-id")
        user = self.request.user
        if not User.has_permission(user, "admin_forum"):
            role = self.request.role
            queryset = queryset.filter(author=role) if role is not None else queryset.none()
        return queryset

    def get_serializer_class(self):
        if self.action == "list":
            return PostListSerializer
        return PostFullSerializer

    def get_permissions(self):
        if self.action == "retrieve":
            return [IsAuthenticated()]
        return super().get_permissions()

    def get_serializer_context(self):
        context = super().get_serializer_context()
        context["safe"] = User.has_permission(self.request.user, "admin_forum")
        return context

    def retrieve(self, request, *args, **kwargs):
        post = self.get_object()
        user = request.user
        role = request.role
        if post.author != role and not User.has_permission(user, "admin_forum"):
            raise PermissionDenied("你没有查看该帖子信息的权限")
        post_serializer = self.get_serializer(post)
        versions = PostVersion.objects.filter(post=post).order_by("id")
        version_serializer = PostVersionListSerializer(versions, many=True, context=self.get_serializer_context())
        return Response(
            {
                "msg": "ok",
                "post": post_serializer.data,
                "versions": version_serializer.data,
            }
        )

    @action(detail=True, methods=["get"], url_path="version/(?P<version_id>[0-9]+)")
    def get_version(self, request, pk, version_id):
        post = self.get_object()
        user = request.user
        role = request.role
        if post.author != role and not User.has_permission(user, "admin_forum"):
            raise PermissionDenied("你没有查看该帖子信息的权限")
        version = get_object_or_404(PostVersion, version=version_id, post=post)
        serializer = PostVersionSerializer(version, context=self.get_serializer_context())
        return Response(serializer.data)

    @action(detail=True, methods=["post"], url_path="pin",
            permission_classes=[IsAuthenticated, HasPermission("admin_forum")])
    def pin(self, request, pk):
        reject_global_reader(request.user)
        pinned = request.data.get("pinned")
        if type(pinned) is not bool:
            raise ValidationError("置顶状态必须为布尔值")
        with transaction.atomic():
            post = self.get_object()
            post = Post.objects.select_for_update().get(pk=post.pk)
            if pinned and post.deleted:
                raise ValidationError("已删除的帖子不能置顶")
            previous = post.pinned
            post.pinned = pinned
            post.save(update_fields=["pinned"])
            record(request.user, "pin_post" if pinned else "unpin_post", object_type="post", object_id=post.pk,
                   details={"before": previous, "after": pinned}, session=request.security_session)
        return Response({"msg": "置顶成功" if pinned else "已取消置顶", "pinned": pinned})

    @action(detail=True, methods=["post"], url_path="review")
    def review(self, request, pk):
        reject_global_reader(request.user)
        serializer = ReviewSerializer(
            data=request.data, context=self.get_serializer_context()
        )
        serializer.is_valid(raise_exception=True)
        post = self.get_object()
        latest_version = post.versions.order_by("id").last()
        if latest_version is None:
            raise ValidationError("帖子版本不存在")
        latest_version.review_status = serializer.validated_data["status"]
        latest_version.save(update_fields=["review_status"])
        latest_version.write_to_post()
        post.review_message.append(serializer.review_data)
        post.save(update_fields=["review_message"])
        return Response({"msg": "ok"})


class PostCommentAdminViewset(GenericViewSet, ListModelMixin, RetrieveModelMixin):
    permission_classes = [HasPermission("admin_forum")]
    serializer_class = PostCommentAdminSerializer
    filter_backends = [DjangoFilterBackend, OrderingFilter, SearchFilter]
    search_fields = ["id", "content"]
    ordering_fields = ["id", "create_time", "like_count", "review_status", "pinned"]

    def get_queryset(self):
        queryset = PostComment.objects.order_by("-id")
        user, role = self.request.user, self.request.role
        if User.has_permission(user, "admin_forum"):
            return queryset
        if role is None:
            return queryset.none()
        return queryset.filter(author=role, post__in=visible_posts(user, role))

    def get_permissions(self):
        if self.action == "retrieve":
            return [IsAuthenticated()]
        return super().get_permissions()

    @action(detail=True, methods=["post"], url_path="review")
    def review(self, request, pk):
        reject_global_reader(request.user)
        serializer = ReviewSerializer(
            data=request.data, context=self.get_serializer_context()
        )
        serializer.is_valid(raise_exception=True)
        comment = self.get_object()
        comment.review_status = serializer.validated_data["status"]
        comment.review_message.append(serializer.review_data)
        comment.save(update_fields=["review_status", "review_message"])
        return Response({"msg": "ok"})
