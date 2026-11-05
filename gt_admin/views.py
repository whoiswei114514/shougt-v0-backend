from django.core.exceptions import ObjectDoesNotExist
from django.core.exceptions import PermissionDenied
from django.utils import timezone
from django.db import transaction
from django.contrib.auth.password_validation import validate_password
from rest_framework.decorators import action
from rest_framework.exceptions import ValidationError
from rest_framework.permissions import BasePermission, IsAuthenticated
from rest_framework.response import Response
from rest_framework.viewsets import GenericViewSet, ModelViewSet
from rest_framework.mixins import UpdateModelMixin, ListModelMixin, RetrieveModelMixin
from gt.permissions import HasPermission, HasPermissionOrReadOnly
from .models import Report, ReportStatusChoice
from .guards import protect_user, protect_role
from .audit import record
from .serializers import (
    ReportCreateSerializer,
    ReportSerializer,
    ReviewSerializer,
    AddCoinRecordSerializer,
)
from gt_auth.models import Role, User
from gt_auth.views import make_user_response
from gt_auth.serializers import (
    PermissionSerializer,
    QuotaSerializer,
    RoleAdminSerializer,
    RoleFullSerializer,
    UserDetailReadSerializer,
)
from gt_forum.models import Post, PostComment, PostVersion
from gt_forum.serializers import (
    PostFullSerializer,
    PostListSerializer,
    PostCommentAdminSerializer,
    PostVersionListSerializer,
    PostVersionSerializer,
)


class ReportPermission(BasePermission):

    def has_permission(self, request, view):
        if view.action in ["create", "retrieve", "list"]:
            return True
        return User.has_permission(request.user, "admin_report")


class ReportViewset(ModelViewSet):
    permission_classes = [IsAuthenticated, ReportPermission]
    filterset_fields = ["status"]

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
        if Report.objects.filter(
            user=user,
            content_type=serializer.validated_data["content_type"],
            content_id=serializer.validated_data["content_id"],
            status=ReportStatusChoice.PENDING,
        ).exists():
            raise ValidationError("你已经举报过该内容")
        try:
            extra_content = Report.get_extra_content(
                serializer.validated_data["content_type"],
                serializer.validated_data["content_id"],
            )
        except ObjectDoesNotExist:
            raise ValidationError("你举报的内容不存在")

        serializer.save(user=user, extra_content=extra_content)
        return Response({"msg": "ok"})

    def perform_update(self, serializer):
        serializer.save(operator=self.request.user, operate_time=timezone.now())


class UserAdminViewset(GenericViewSet, UpdateModelMixin, ListModelMixin):
    queryset = User.objects.order_by("id")
    permission_classes = [HasPermission("admin_user")]
    serializer_class = UserDetailReadSerializer
    search_fields = ["real_name", "^username", "^student_id"]

    def create(self, request, *args, **kwargs):
        from .user_creation import create_user
        return Response(create_user(request), status=201)

    def retrieve(self, request, *args, **kwargs):
        return make_user_response(self.get_object(), False, False)

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
        if user.is_management and not request.user.permission.super_admin:
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
            f"管理员{request.user.id}操作：{serializer.validated_data['detail']}",
            allow_negative=True,
        )
        return Response({"msg": "ok"})

    @action(detail=True, methods=["post"], url_path="ban")
    def ban(self, request, pk):
        is_active = request.data.get("is_active")
        user: User = self.get_object()
        protect_user(request.user, user)
        if type(is_active) is not bool:
            raise ValidationError("封禁状态格式错误")
        user.is_active = is_active
        user.version += 1
        user.save()
        return Response({"msg": "ok"})


class RoleAdminViewset(
    GenericViewSet, ListModelMixin, RetrieveModelMixin, UpdateModelMixin
):
    queryset = Role.objects.order_by("id")
    permission_classes = [HasPermission("admin_role")]
    search_fields = ["id", "name"]

    def perform_update(self, serializer):
        protect_role(self.request.user, serializer.instance)
        serializer.save()

    def get_serializer_class(self):
        if self.action == "retrieve":
            return RoleFullSerializer
        return RoleAdminSerializer


class PostAdminViewset(GenericViewSet, ListModelMixin, RetrieveModelMixin):
    permission_classes = [IsAuthenticated, HasPermissionOrReadOnly("admin_forum")]
    search_fields = ["id", "title", "content"]

    def get_queryset(self):
        queryset = Post.objects.order_by("-id")
        user = self.request.user
        if not User.has_permission(user, "admin_forum"):
            queryset = queryset.filter(author=self.request.role)
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
        context["safe"] = True
        return context

    def retrieve(self, request, *args, **kwargs):
        post = self.get_object()
        user = request.user
        role = request.role
        if post.author != role and not User.has_permission(user, "admin_forum"):
            raise PermissionDenied("你没有查看该帖子信息的权限")
        post_serializer = self.get_serializer(post)
        versions = PostVersion.objects.filter(post=post).order_by("id")
        version_serializer = PostVersionListSerializer(versions, many=True)
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
        version = PostVersion.objects.get(version=version_id, post=post)
        serializer = PostVersionSerializer(version)
        return Response(serializer.data)

    @action(detail=True, methods=["post"], url_path="pin",
            permission_classes=[IsAuthenticated, HasPermission("admin_forum")])
    def pin(self, request, pk):
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
        serializer = ReviewSerializer(
            data=request.data, context=self.get_serializer_context()
        )
        serializer.is_valid(raise_exception=True)
        post = self.get_object()
        latest_version = post.versions.order_by("id").last()
        latest_version.review_status = serializer.validated_data["status"]
        latest_version.save(update_fields=["review_status"])
        latest_version.write_to_post()
        post.review_message.append(serializer.review_data)
        post.save(update_fields=["review_message"])
        return Response({"msg": "ok"})


class PostCommentAdminViewset(GenericViewSet, ListModelMixin, RetrieveModelMixin):
    queryset = PostComment.objects.order_by("-id")
    permission_classes = [HasPermission("admin_forum")]
    serializer_class = PostCommentAdminSerializer
    search_fields = ["id", "content"]

    def get_permissions(self):
        if self.action == "retrieve":
            return [IsAuthenticated()]
        return super().get_permissions()

    def retrieve(self, request, *args, **kwargs):
        comment = self.get_object()
        user = request.user
        role = request.role
        if comment.author != role and not User.has_permission(user, "admin_forum"):
            raise PermissionDenied("你没有查看该评论信息的权限")
        return super().retrieve(request, *args, **kwargs)

    @action(detail=True, methods=["post"], url_path="review")
    def review(self, request, pk):
        serializer = ReviewSerializer(
            data=request.data, context=self.get_serializer_context()
        )
        serializer.is_valid(raise_exception=True)
        comment = self.get_object()
        comment.review_status = serializer.validated_data["status"]
        comment.review_message.append(serializer.review_data)
        comment.save(update_fields=["review_status", "review_message"])
        return Response({"msg": "ok"})
