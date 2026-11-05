from datetime import timedelta
from django.utils import timezone
from django.conf import settings
from django.db import transaction
from django.shortcuts import get_object_or_404
from .visibility import visible_posts, visible_comments
from rest_framework.decorators import action
from rest_framework.viewsets import ModelViewSet
from rest_framework.permissions import IsAuthenticatedOrReadOnly
from rest_framework.exceptions import AuthenticationFailed, ValidationError
from rest_framework.response import Response
from rest_framework.filters import OrderingFilter, SearchFilter
from django_filters import rest_framework as filters

from .models import (
    Post,
    PostComment,
    PostLike,
    PostTypeChoice,
    PostShareWithChoice,
    PostCoinRecord,
    PostVersion,
)
from .serializers import (
    PostFullSerializer,
    PostVersionSerializer,
    PostListSerializer,
    PostLikedByField,
    PostCommentSerializer,
    PostCommentCreateSerializer,
)
from .tasks import review_post_version, review_post_comment
from gt_admin._models import ReviewStatusChoice
from gt_auth.models import IdentityChoice, User, Role
from gt.permissions import HaveRoleOrReadOnly, Hccaptcha, IsServer
from gt.paginations import PageNumberPagination_10, PageNumberPagination
from gt_coin.serializers import DonateCoinSerializer
from gt_coin.models import CoinRecordType, Coin
import gt_coin.amount as coin_amount


class PostFilter(filters.FilterSet):
    author = filters.NumberFilter(method="filter_author")
    liked_by = filters.NumberFilter(method="filter_liked_by")

    def filter_author(self, queryset, name, value):
        author = Role.objects.filter(id=value, deleted=False).first()
        if author is None:
            return queryset.none()
        user = self.request.user
        if author.is_private and not author.is_member(user):
            return queryset.none()
        return queryset.filter(author_id=value)

    def filter_liked_by(self, queryset, name, value):
        role = Role.objects.filter(id=value, deleted=False).first()
        if role is None:
            return queryset.none()
        user = self.request.user
        if (role.is_private or not role.show_like) and not role.is_member(user):
            return queryset.none()
        return queryset.filter(liked_by__role_id=value)

    class Meta:
        model = Post
        fields = {
            "type": ["exact"],
            "review_status": ["exact"],
        }


class PostOrdering(OrderingFilter):

    def filter_queryset(self, request, queryset, view):
        ordering = self.get_ordering(request, queryset, view)
        ordering = ["-pinned"] + ordering

        if ordering:
            return queryset.order_by(*ordering)

        return queryset


class PostViewset(ModelViewSet):
    permission_classes = [IsAuthenticatedOrReadOnly, HaveRoleOrReadOnly]
    search_fields = ["title", "content", "author__name"]
    filterset_class = PostFilter
    filter_backends = [filters.DjangoFilterBackend, PostOrdering, SearchFilter]
    ordering_fields = ["create_time", "update_time", "like_count", "comment_count"]
    ordering = ["-create_time"]
    pagination_class = PageNumberPagination

    def get_serializer_class(self):
        if self.action == "list":
            return PostListSerializer
        return PostFullSerializer

    def get_permissions(self):
        permissions = super().get_permissions()
        if self.action in ["create", "update", "partial_update"]:
            permissions.append((Hccaptcha | IsServer)())
        return permissions

    def get_queryset(self):
        queryset = Post.objects.filter(deleted=False)
        user = self.request.user
        role = self.request.role

        if self.action in ["destroy", "update", "partial_update"]:
            return queryset.filter(author=role, deleted=False)

        return visible_posts(user, role)

    def get_object(self):
        pk = self.kwargs.get("pk")
        if pk.isdigit():
            return super().get_object()
        return get_object_or_404(self.get_queryset(), alias=pk)

    def retrieve(self, request, *args, **kwargs):
        post = self.get_object()
        if self.request.GET.get("for") == "edit" and request.role and post.author_id == request.role.id:
            post_version = PostVersion.objects.get(
                post=post, version=post.latest_version
            )
            return Response(PostVersionSerializer(post_version).data)
        return super().retrieve(request, *args, **kwargs)

    def create(self, request, *args, **kwargs):
        source = request.source
        user = request.user
        role = request.role

        time = timezone.now()
        quota = {"post_24h_count_limit": user.quota.post_24h_count_limit * (settings.NO_REVIEW_QUOTA_MULTIPLIER if User.has_permission(user, "no_review") else 1)}
        recent_posts = PostVersion.objects.filter(
            create_time__gte=time - timedelta(days=1),
            version=1,
            user=user,
        )

        if recent_posts.count() >= quota["post_24h_count_limit"]:
            return Response(
                {
                    "msg": f"用户24小时累计发布帖子数量已达上限({quota['post_24h_count_limit']}条)",
                },
                status=400,
            )

        serializer = PostVersionSerializer(data=request.data, context={"request": request})
        serializer.is_valid(raise_exception=True)
        create_time = time
        if request.is_server and serializer.validated_data.get("time"):
            create_time = serializer.validated_data["time"]
        serializer.save(
            user=user, review_status=ReviewStatusChoice.PENDING, create_time=create_time
        )
        post_version = serializer.instance
        post = Post.objects.create(
            author=role,
            title=post_version.title,
            content=post_version.content,
            type=serializer.validated_data["post_type"],
            media_type=serializer.validated_data["media_type"],
            images=post_version.images,
            video_id=post_version.video_id,
            share_with=post_version.share_with,
            allow_comment=post_version.allow_comment,
            source=source,
            review_status=ReviewStatusChoice.PENDING,
            create_time=create_time,
            edit_time=create_time,
            update_time=time,
        )
        post_version.post_id = post.id
        if (
            post_version.share_with == PostShareWithChoice.PRIVATE
            or User.has_permission(user, "no_review")
        ):
            post_version.review_status = ReviewStatusChoice.NO_NEED
            post_version.save()
            post_version.write_to_post()
        else:
            post_version.save()
        if post_version.review_status == ReviewStatusChoice.PENDING:
            review_post_version.delay(post_version.id)
        return Response(
            {
                "msg": "ok",
                "data": {"id": post.id, "type": post.type},
            }
        )

    def update(self, request, *args, **kwargs):
        user = request.user
        post = self.get_object()
        if not request.user.roles.filter(role_id=post.author_id).exists():
            raise AuthenticationFailed("当前角色不是该帖子的作者")
        serializer = PostVersionSerializer(data=request.data, context={"request": request, "existing_post": post})
        serializer.is_valid(raise_exception=True)

        post.latest_version += 1
        post.save(update_fields=["latest_version"])
        extra_fields = {
            "user": user,
            "post_id": post.id,
            "version": post.latest_version,
            "review_status": ReviewStatusChoice.PENDING,
        }
        if serializer.validated_data[
            "share_with"
        ] == PostShareWithChoice.PRIVATE or User.has_permission(user, "no_review"):
            extra_fields["review_status"] = ReviewStatusChoice.NO_NEED
        serializer.save(**extra_fields)
        post_version = serializer.instance
        if post_version.review_status >= ReviewStatusChoice.NO_NEED:
            post_version.write_to_post()
        else:
            review_post_version.delay(post_version.id)

        return Response(
            {
                "msg": "ok",
                "data": {"id": post.id, "type": post.type},
            }
        )

    def destroy(self, request, *args, **kwargs):
        instance = self.get_object()
        instance.deleted = True
        instance.save(update_fields=["deleted"])
        return Response({"msg": "ok"})

    @action(
        detail=True,
        methods=["get", "post"],
        url_path="like",
    )
    def like(self, request, *args, **kwargs):
        post = self.get_object()
        role = request.role
        if request.method == "GET":
            return Response(
                {
                    "msg": "ok",
                    "liked": post.liked_by.filter(role=role, liked=True).exists(),
                    "like_count": post.like_count,
                    "liked_by": PostLikedByField().to_representation(post),
                }
            )
        post_like, created = PostLike.objects.get_or_create(post=post, role=role)
        if created:
            post.like_count += 1
            post_like.create_notification()
        else:
            post_like.liked = not post_like.liked
            post_like.save(update_fields=["liked"])
            post.like_count += 1 if post_like.liked else -1
        post.save(
            update_fields=["like_count", "update_time"] if created else ["like_count"]
        )
        return Response(
            {
                "msg": "ok",
                "liked": post_like.liked,
                "like_count": post.like_count,
                "liked_by": PostLikedByField().to_representation(post),
            }
        )

    @action(detail=True, methods=["post"], url_path="donate")
    @transaction.atomic
    def donate(self, request, *args, **kwargs):
        serializer = DonateCoinSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        instance = Post.objects.select_for_update().get(pk=self.get_object().pk)
        user = request.user
        recipient = instance.author.owner
        list(Coin.objects.select_for_update().filter(pk__in=[user.coin_id, recipient.coin_id]).order_by("pk"))
        post_coin_record, created = PostCoinRecord.objects.get_or_create(
            post=instance, user=user
        )
        if serializer.validated_data["amount"] == post_coin_record.amount:
            return Response({"msg": "ok"})
        elif serializer.validated_data["amount"] < post_coin_record.amount:
            raise ValidationError("不能撤销已送出的硬币")
        change = serializer.validated_data["amount"] - post_coin_record.amount
        user.coin.add_record(
            -change,
            CoinRecordType.DONATE,
            f"向帖子[{instance.id}]投币",
        )
        instance.coin_count += change
        instance.save(update_fields=["coin_count"])
        post_coin_record.amount = serializer.validated_data["amount"]
        post_coin_record.save(update_fields=["amount"])
        recipient.coin.add_record(
            change * coin_amount.DONATE_RATE,
            CoinRecordType.DONATE,
            f"帖子[{instance.id}]收到投币",
        )
        return Response({"msg": "ok"})


class CommentFilter(filters.FilterSet):
    post = filters.NumberFilter(method="filter_post")
    parent = filters.NumberFilter(method="filter_parent")
    start = filters.NumberFilter(field_name="id", lookup_expr="gt")

    def filter_post(self, queryset, name, value):
        return queryset.filter(post_id=value).order_by("-pinned", "id")

    def filter_parent(self, queryset, name, value):
        if value != 0:
            return queryset.filter(parent_id=value)
        elif self.request.GET.get("deep") != "true":
            return queryset.filter(parent_id=None)
        return queryset

    def __init__(self, data=None, queryset=None, *, request=None, prefix=None):
        if data is not None:
            data = data.copy()
            data.setdefault("parent", 0)
        super().__init__(data, queryset, request=request, prefix=prefix)

    class Meta:
        model = PostComment
        fields = {
            "review_status": ["exact", "in"],
        }


class CommentOrdering(OrderingFilter):

    def filter_queryset(self, request, queryset, view):
        ordering = self.get_ordering(request, queryset, view)
        ordering = ["-pinned"] + ordering + ["id"]

        if ordering:
            return queryset.order_by(*ordering)

        return queryset


class CommentViewset(ModelViewSet):
    permission_classes = [IsAuthenticatedOrReadOnly, HaveRoleOrReadOnly]
    # Only the explicit create/delete/like/pin flows may mutate a comment.
    http_method_names = ["get", "post", "delete", "head", "options"]
    filterset_class = CommentFilter
    filter_backends = [filters.DjangoFilterBackend, CommentOrdering]
    pagination_class = PageNumberPagination_10
    ordering_fields = ["create_time", "like_count"]
    ordering = ["create_time"]
    serializer_class = PostCommentSerializer

    def get_queryset(self):
        return visible_comments(self.request.user, self.request.role)

    def filter_queryset(self, queryset):
        if self.action == "destroy":
            return queryset.filter(author=self.request.role)
        return super().filter_queryset(queryset)

    def get_serializer_context(self):
        context = super().get_serializer_context()
        context["children"] = self.request.GET.get("children") != "false"
        return context

    # def retrieve(self, request, *args, **kwargs):
    #     pk = self.kwargs.get("pk")
    #     comment = self.get_queryset().get(id=pk)
    #     if comment.parent:
    #         comment = comment.parent
    #     post = comment.post
    #     return Response(
    #         {
    #             "msg": "ok",
    #             "comment": self.get_serializer(
    #                 comment,
    #                 context={"children": 10, **self.get_serializer_context()},
    #             ).data,
    #             "post": PostListSerializer(
    #                 post, context=self.get_serializer_context()
    #             ).data,
    #         }
    #     )

    @action(
        detail=True,
        filterset_class=None,
        methods=["post"],
        url_path="like",
    )
    def like(self, request, *args, **kwargs):
        instance = self.get_object()
        role = request.role
        if not instance.liked_by.filter(id=role.id).exists():
            instance.liked_by.add(role)
            instance.like_count += 1
            liked = True
            instance.create_like_notification(role)
        else:
            instance.liked_by.remove(role)
            instance.like_count -= 1
            liked = False
        instance.save(update_fields=["like_count"])
        return Response(
            {
                "msg": "ok",
                "liked": liked,
                "like_count": instance.like_count,
            }
        )

    def create(self, request, *args, **kwargs):
        user = request.user
        quota = {"comment_24h_count_limit": user.quota.comment_24h_count_limit * (settings.NO_REVIEW_QUOTA_MULTIPLIER if User.has_permission(user, "no_review") else 1)}
        time = timezone.now()
        recent_comments = PostComment.objects.filter(
            create_time__gte=time - timedelta(days=1),
            user=user,
        )
        if recent_comments.count() >= quota["comment_24h_count_limit"]:
            return Response(
                {
                    "msg": f"用户24小时累计发布评论数量已达上限({quota['comment_24h_count_limit']}条)",
                },
                status=400,
            )
        role = request.role
        serializer = PostCommentCreateSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        post = serializer.validated_data["post"]
        if not visible_posts(user, role).filter(pk=post.pk, allow_comment=True).exists():
            raise ValidationError("帖子不可见或已关闭评论")
        reply_to = serializer.validated_data.get("reply_to")
        if reply_to and (reply_to.post_id != post.pk or not visible_comments(user, role).filter(pk=reply_to.pk).exists()):
            raise ValidationError("回复的评论不属于当前可见帖子")
        private_member = post.share_with == PostShareWithChoice.PRIVATE and post.author.is_member(user)
        if role.is_private and post.author != role and not private_member:
            return Response(
                {"msg": "匿名角色不能发表评论"},
                status=403,
            )

        reply_to = serializer.validated_data.get("reply_to")
        parent = None
        depth = 1
        if reply_to:
            parent = reply_to.parent if reply_to.depth > 1 else reply_to
            depth = reply_to.depth + 1
        review_status = ReviewStatusChoice.PENDING
        if private_member or User.has_permission(user, "no_review"):
            review_status = ReviewStatusChoice.NO_NEED
        serializer.save(
            author=role,
            parent=parent,
            depth=depth,
            user=user,
            review_status=review_status,
        )
        post = serializer.instance.post
        post.comment_count += 1
        post.save(update_fields=["comment_count", "update_time"])
        if review_status == ReviewStatusChoice.PENDING:
            review_post_comment.delay(serializer.instance.id)

        return Response(
            {
                "msg": "ok",
                "data": PostCommentSerializer(
                    serializer.instance, context={"request": request}
                ).data,
            }
        )

    def destroy(self, request, *args, **kwargs):
        instance = self.get_object()
        role = request.role
        if instance.author != role and instance.post.author != role:
            return Response({"msg": "当前角色不是评论或帖子作者"}, status=403)
        instance.deleted = True
        # if (
        #     instance.parent is None
        #     and not PostComment.objects.filter(parent=instance).exists()
        # ):
        #     instance.hidden = True
        instance.save(update_fields=["deleted", "hidden"])
        return Response({"msg": "ok"})

    @action(
        detail=True,
        methods=["post"],
        url_path="pin",
        filterset_class=None,
    )
    def pin(self, request, *args, **kwargs):
        instance = self.get_object()
        role = request.role
        if instance.post.author != role:
            return Response({"msg": "当前角色不是帖子作者"}, status=403)
        elif instance.depth != 1:
            return Response({"msg": "只能置顶一级评论"}, status=400)
        instance.pinned = not instance.pinned
        instance.save(update_fields=["pinned"])
        return Response({"msg": "ok", "pinned": instance.pinned})
