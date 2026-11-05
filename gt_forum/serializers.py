from django.db.models import Q
from rest_framework import serializers
from .models import (
    Post,
    PostLike,
    PostComment,
    PostVersion,
    PostTypeChoice,
    PostCoinRecord,
    PostMediaTypeChoice,
)
from gt_admin._models import ReviewStatusChoice
from gt_auth.serializers import RoleSerializer, RoleBriefSerializer, UserBriefSerializer
from gt_auth.models import Role, User
from gt_file.serializers import ImageViewSerializer, VideoSerializer
from gt_file.models import Image, Video
from gt_file.doge_api import generate_playtoken


class PostImageField(serializers.ReadOnlyField):
    def to_representation(self, value):
        images = Image.objects.filter(id__in=value)
        data = ImageViewSerializer(images, many=True).data
        data.sort(key=lambda x: value.index(x["id"]))
        return data


class PostVideoField(serializers.ReadOnlyField):
    def to_representation(self, value):
        if not value:
            return None
        video = Video.objects.get(id=value)
        return VideoSerializer(video).data


class PostLikedField(serializers.ReadOnlyField):
    def to_representation(self, obj: Post):
        if self.context.get("request"):
            return obj.liked_by_role(self.context["request"].role)
        return False


class PostLikedByField(serializers.ReadOnlyField):
    def to_representation(self, obj):
        _roles = list(
            PostLike.objects.filter(post=obj, liked=True)
            .order_by("create_time")[:20]
            .values_list("role_id", flat=True)
        )
        roles = Role.objects.filter(id__in=_roles)
        data = RoleBriefSerializer(roles, many=True).data
        return data


class PostCommentLikedField(serializers.ReadOnlyField):
    def to_representation(self, obj: PostComment):
        return obj.liked_by_role(self.context["request"].role)


class PostCommentBriefSerializer(serializers.ModelSerializer):
    author = RoleBriefSerializer()

    class Meta:
        model = PostComment
        fields = read_only_fields = ["id", "author"]


class PostCommentReplyToField(serializers.ReadOnlyField):
    def to_representation(self, obj):
        if obj.depth >= 3:
            # if obj.reply_to.deleted:
            #     return {"id": obj.reply_to.id, "author": None}
            # else:
            #     return PostCommentBriefSerializer(obj.reply_to).data
            return PostCommentBriefSerializer(obj.reply_to, context=self.context).data
        return None


class PostCommentSerializer(serializers.ModelSerializer):
    # author = serializers.SerializerMethodField()
    author = RoleBriefSerializer()
    content = serializers.SerializerMethodField()
    children = serializers.SerializerMethodField()
    children_count = serializers.SerializerMethodField()
    liked = PostCommentLikedField(source="*")
    reply_to = PostCommentReplyToField(source="*")

    def get_author(self, obj):
        if obj.deleted:
            return None
        return RoleBriefSerializer(obj.author, context=self.context).data

    def get_content(self, obj):
        if obj.deleted or (
            not self.context.get("safe")
            and not (
                self.context.get("request")
                and self.context["request"].role == obj.author
            )
            and obj.review_status < ReviewStatusChoice.NO_NEED
        ):
            return None
        return obj.content

    def get_children(self, obj):
        if self.context.get("children") == False:
            return None
        if obj.depth != 1:
            return []
        from .visibility import visible_comments
        request = self.context.get("request")
        allowed = visible_comments(request.user, request.role) if request else PostComment.objects.none()
        queryset = (
            obj.related_comments.filter(pk__in=allowed)
            .select_related("author", "reply_to")
            .order_by("id")[: self.context.get("children", 3)]
        )
        return PostCommentSerializer(queryset, many=True, context=self.context).data

    def get_children_count(self, obj):
        if obj.depth != 1 or self.context.get("children") == False:
            return -1
        from .visibility import visible_comments
        request = self.context.get("request")
        if not request:
            return 0
        return obj.related_comments.filter(pk__in=visible_comments(request.user, request.role)).count()

    class Meta:
        model = PostComment
        exclude = [
            "post",
            "liked_by",
            "parent",
            "review_message",
            "user",
            "update_time",
        ]


class PostCommentCreateSerializer(serializers.ModelSerializer):
    class Meta:
        model = PostComment
        fields = ["content", "post", "reply_to"]


class PostBriefSerializer(serializers.ModelSerializer):
    brief_content = serializers.SerializerMethodField()

    def get_brief_content(self, obj):
        return obj.title or obj.content[:200]

    class Meta:
        model = Post
        fields = ["id", "brief_content"]


class PostCommentAdminSerializer(serializers.ModelSerializer):
    author = RoleBriefSerializer()
    user = UserBriefSerializer()
    post = PostBriefSerializer()

    class Meta:
        model = PostComment
        exclude = ["liked_by"]


# PostModelSerializer


class PostCoinRecordField(serializers.ReadOnlyField):
    def to_representation(self, obj):
        user = self.context.get("user") or (
            self.context.get("request") and self.context["request"].user
        )
        if not user or not user.is_authenticated:
            return 0
        record = PostCoinRecord.objects.filter(post=obj, user=user).first()
        if not record:
            return 0
        return record.amount


class PostListSerializer(serializers.ModelSerializer):
    author = RoleBriefSerializer()
    image_items = PostImageField(source="images")
    video_item = PostVideoField(source="video_id")
    content = serializers.SerializerMethodField()
    liked = PostLikedField(source="*")
    coin_record = PostCoinRecordField(source="*")

    def get_content(self, obj):
        if obj.type == PostTypeChoice.MOMENT:
            return obj.content
        return obj.content[:200]

    class Meta:
        model = Post
        exclude = ["review_message", "images", "video_id"]


class PostFullSerializer(serializers.ModelSerializer):
    author = RoleSerializer()
    image_items = PostImageField(source="images")
    video_item = PostVideoField(source="video_id")
    liked = PostLikedField(source="*")
    liked_by = PostLikedByField(source="*")
    review_message = serializers.SerializerMethodField()
    coin_record = PostCoinRecordField(source="*")

    def get_review_message(self, obj):
        review_message = obj.review_message
        if not (
            self.context.get("request")
            and User.has_permission(self.context["request"].user, "admin_forum")
        ):
            for m in review_message:
                if m.get("reviewer_type") == "admin" and "reviewer" in m:
                    m.pop("reviewer")
        return review_message

    class Meta:
        model = Post
        exclude = ["images", "video_id"]


class PostEditSerializer(serializers.ModelSerializer):
    class Meta:
        model = Post
        fields = ["id", "type", "media_type", "author"]


class PostVersionSerializer(serializers.ModelSerializer):
    image_items = PostImageField(source="images")
    video_item = PostVideoField(source="video_id")
    post = PostEditSerializer(read_only=True)
    user = UserBriefSerializer(read_only=True)
    post_type = serializers.ChoiceField(choices=PostTypeChoice.choices, write_only=True)
    media_type = serializers.ChoiceField(
        choices=PostMediaTypeChoice.choices, write_only=True
    )
    time = serializers.DateTimeField(write_only=True, required=False)

    def validate(self, attrs):
        attrs = super().validate(attrs)
        if attrs["post_type"] == PostTypeChoice.MOMENT and len(attrs["content"]) > 2000:
            raise serializers.ValidationError("动态内容不能超过2000字")
        request, existing = self.context.get("request"), self.context.get("existing_post")
        image_ids = attrs.get("images", [])
        if (not isinstance(image_ids, list) or len(image_ids) > 100 or
                any(type(image_id) is not int or image_id <= 0 for image_id in image_ids) or
                len(image_ids) != len(set(image_ids))):
            raise serializers.ValidationError("图片列表需为最多 100 个不重复的图片编号")
        if request and image_ids:
            retained = set(existing.images) if existing else set()
            if existing:
                for previous in existing.versions.values_list("images", flat=True):
                    retained.update(previous)
            available = set(Image.objects.filter(pk__in=image_ids, is_banned=False).filter(
                Q(user=request.user) | Q(pk__in=retained)
            ).values_list("id", flat=True))
            if set(image_ids) - available:
                raise serializers.ValidationError("只能使用自己上传的图片，或保留本帖已有图片")
        video_id = attrs.get("video_id")
        if request and video_id:
            owned = Video.objects.filter(pk=video_id, user=request.user).exists()
            retained = existing and (existing.video_id == video_id or
                                     existing.versions.filter(video_id=video_id).exists())
            if not owned and not retained:
                raise serializers.ValidationError("只能使用自己上传的视频，或保留本帖已有视频")
        return attrs

    def create(self, validated_data):
        validated_data.pop("post_type")
        validated_data.pop("media_type")
        return super().create(validated_data)

    def save(self, **kwargs):
        if self.validated_data.get("time"):
            self.validated_data.pop("time")
        return super().save(**kwargs)

    class Meta:
        model = PostVersion
        fields = [
            "id",
            "user",
            "post",
            "title",
            "content",
            "post_type",
            "media_type",
            "images",
            "image_items",
            "video_id",
            "video_item",
            # "tags",
            "share_with",
            "allow_comment",
            "review_status",
            "create_time",
            "version",
            "time",
        ]
        read_only_fields = [
            "id",
            "image_items",
            "video_item",
            "post",
            "user",
            "review_status",
            "create_time",
            "version",
        ]


class PostVersionListSerializer(serializers.ModelSerializer):
    user = UserBriefSerializer()

    class Meta:
        model = PostVersion
        fields = ["id", "version", "user", "create_time", "review_status"]
