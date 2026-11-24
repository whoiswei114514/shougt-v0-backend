from django.db import models
from django.utils import timezone
from gt_auth.models import Role, SourceChoice, User, Notification, NotificationType
from gt_admin._models import ReviewStatusChoice


class PostShareWithChoice(models.IntegerChoices):
    ROLES = -4, "Roles"
    PRIVATE = -3, "Private"
    STUDENT = -2, "Student"
    SCHOOL = -1, "School"
    PUBLIC = 0, "Public"


class PostTypeChoice(models.IntegerChoices):
    MOMENT = 1, "Moment"
    ARTICLE = 2, "Article"


class PostMediaTypeChoice(models.IntegerChoices):
    IMAGE = 0, "Image"
    LINK = 1, "Link"
    VIDEO = 2, "Video"
    BILIBILI = 3, "Bilibili"


class Post(models.Model):
    title = models.CharField(max_length=300, blank=True)
    content = models.TextField(max_length=50000)
    type = models.IntegerField(choices=PostTypeChoice.choices)
    alias = models.CharField(max_length=300, null=True, unique=True)

    images = models.JSONField(default=list)  # Image ID list (int[])
    video_id = models.IntegerField(null=True)
    media_type = models.IntegerField(
        choices=PostMediaTypeChoice.choices, default=PostMediaTypeChoice.IMAGE
    )

    tags = models.JSONField(default=list)
    author = models.ForeignKey(
        Role,
        on_delete=models.SET_NULL,
        related_name="posts",
        null=True,
    )

    read_count = models.IntegerField(default=0)
    like_count = models.IntegerField(default=0)
    comment_count = models.IntegerField(default=0)
    allow_comment = models.BooleanField(default=True)
    coin_count = models.IntegerField(default=0)

    current_version = models.IntegerField(default=1)
    latest_version = models.IntegerField(default=1)
    real_version = models.IntegerField(default=1)

    source = models.CharField(choices=SourceChoice.choices, max_length=20, null=True)
    review_status = models.IntegerField(
        choices=ReviewStatusChoice.choices,
        default=ReviewStatusChoice.NO_NEED,
    )
    review_message = models.JSONField(default=list)
    share_with = models.IntegerField(
        choices=PostShareWithChoice.choices,
        default=PostShareWithChoice.PUBLIC,
    )
    visible_roles = models.ManyToManyField(
        Role, blank=True, related_name="role_visible_posts"
    )
    pinned = models.BooleanField(default=False)
    deleted = models.BooleanField(default=False)

    create_time = models.DateTimeField(default=timezone.now)
    edit_time = models.DateTimeField(default=timezone.now)
    update_time = models.DateTimeField(auto_now=True)

    def liked_by_role(self, role: Role | None):
        if not role:
            return False
        if not hasattr(role, "liked_post_ids"):
            role.liked_post_ids = PostLike.objects.filter(
                role=role, liked=True
            ).values_list("post_id", flat=True)
        return self.id in role.liked_post_ids

    def update_review_status(self, status, version_only=False):
        self.versions.filter(
            review_status__in=[
                ReviewStatusChoice.PENDING,
                ReviewStatusChoice.PENDING_RECHECK,
            ]
        ).update(review_status=status)
        if status >= ReviewStatusChoice.NO_NEED:
            self.versions.filter(
                review_status__gte=ReviewStatusChoice.NO_NEED
            ).order_by("-version").first().write_to_post()
        else:
            if not version_only or self.review_status in [
                ReviewStatusChoice.PENDING,
                ReviewStatusChoice.PENDING_RECHECK,
            ]:
                self.review_status = status
            self.current_version = self.latest_version
            self.save(update_fields=["review_status", "current_version"])


class PostVersion(models.Model):
    user = models.ForeignKey(
        User, on_delete=models.SET_NULL, null=True, related_name="post_versions"
    )
    post = models.ForeignKey(
        Post, on_delete=models.CASCADE, related_name="versions", null=True
    )
    title = models.CharField(max_length=300, blank=True)
    content = models.TextField(max_length=50000)
    images = models.JSONField(null=True)
    video_id = models.IntegerField(null=True)

    share_with = models.IntegerField(choices=PostShareWithChoice.choices, null=True)
    visible_role_ids = models.JSONField(default=list)
    allow_comment = models.BooleanField(default=True)

    review_status = models.IntegerField(
        choices=ReviewStatusChoice.choices,
        default=ReviewStatusChoice.PENDING,
    )

    create_time = models.DateTimeField(default=timezone.now)
    version = models.IntegerField(default=1)

    def write_to_post(self):
        post = self.post
        post.title = self.title
        post.content = self.content
        post.images = self.images
        post.video_id = self.video_id
        post.share_with = self.share_with
        post.allow_comment = self.allow_comment
        post.review_status = self.review_status
        post.real_version = self.version
        post.current_version = self.version
        post.edit_time = self.create_time
        post.save(
            update_fields=[
                "title",
                "content",
                "images",
                "video_id",
                "share_with",
                "allow_comment",
                "review_status",
                "real_version",
                "current_version",
                "edit_time",
                "update_time",
            ]
        )
        if self.share_with == PostShareWithChoice.ROLES:
            post.visible_roles.set(self.visible_role_ids or [])
        else:
            post.visible_roles.clear()


class PostLike(models.Model):
    post = models.ForeignKey(Post, on_delete=models.CASCADE, related_name="liked_by")
    role = models.ForeignKey(Role, on_delete=models.CASCADE, related_name="liked_posts")

    create_time = models.DateTimeField(auto_now_add=True)
    liked = models.BooleanField(default=True)

    def create_notification(self):
        if not self.post.author_id or self.post.author_id == self.role_id:
            return
        q = Notification.objects.filter(
            role=self.post.author,
            type=NotificationType.POST_LIKE,
            content__post_id=self.post.id,
            is_read=False,
        )
        if q.exists():
            obj = q.first()
            if self.role.name not in obj.content["role_names"]:
                obj.content["role_names"].append(self.role.name)
                obj.save()
        else:
            Notification.objects.create(
                role=self.post.author,
                type=NotificationType.POST_LIKE,
                content={
                    "post_id": self.post.id,
                    "post_type": self.post.type,
                    "role_names": [self.role.name],
                    "post_info": self.post.title or self.post.content[:20],
                },
            )


class PostComment(models.Model):
    content = models.TextField(max_length=600)
    user = models.ForeignKey(
        User, on_delete=models.SET_NULL, null=True, related_name="post_comments"
    )
    author = models.ForeignKey(
        Role, on_delete=models.SET_NULL, null=True, related_name="post_comments"
    )

    post = models.ForeignKey(Post, on_delete=models.CASCADE, related_name="comments")
    parent = models.ForeignKey(
        "self", on_delete=models.CASCADE, null=True, related_name="related_comments"
    )
    reply_to = models.ForeignKey(
        "self", on_delete=models.CASCADE, null=True, related_name="replies"
    )
    depth = models.IntegerField(default=1)

    like_count = models.BigIntegerField(default=0)
    liked_by = models.ManyToManyField(Role, related_name="liked_post_comments")

    review_status = models.IntegerField(
        choices=ReviewStatusChoice.choices,
        default=ReviewStatusChoice.NO_NEED,
    )
    review_message = models.JSONField(
        default=list
    )  # reviewer, reviewer_time, time, message, status

    create_time = models.DateTimeField(auto_now_add=True)
    update_time = models.DateTimeField(auto_now=True)

    pinned = models.BooleanField(default=False)
    deleted = models.BooleanField(default=False)
    hidden = models.BooleanField(default=False)

    def liked_by_role(self, role: Role | None):
        if not role:
            return False
        if not hasattr(role, "liked_post_comment_ids"):
            role.liked_post_comment_ids = role.liked_post_comments.values_list(
                "id", flat=True
            )
        return self.id in role.liked_post_comment_ids

    def create_like_notification(self, role: Role):
        if not self.author_id or self.author_id == role.id:
            return
        q = Notification.objects.filter(
            role=self.author,
            type=NotificationType.COMMENT_LIKE,
            content__comment_id=self.id,
            is_read=False,
        )
        if q.exists():
            obj = q.first()
            if role.name not in obj.content["role_names"]:
                obj.content["role_names"].append(role.name)
                obj.save()
        else:
            Notification.objects.create(
                role=self.author,
                type=NotificationType.COMMENT_LIKE,
                content={
                    "post_id": self.post.id,
                    "post_type": self.post.type,
                    "comment_id": self.id,
                    "role_names": [role.name],
                    "comment_info": self.content[:50],
                },
            )

    def create_reply_notification(self):
        reply_to = self.reply_to
        if not self.author_id or reply_to is None or not reply_to.author_id or reply_to.author_id == self.author_id:
            return
        Notification.objects.create(
            role=reply_to.author,
            type=NotificationType.COMMENT_REPLY,
            content={
                "post_id": self.post.id,
                "post_type": self.post.type,
                "reply_comment_id": self.id,
                "reply_comment_info": self.content[:50],
                "reply_author_name": self.author.name,
            },
        )

    def create_post_comment_notification(self):
        if not self.author_id or not self.post.author_id or self.post.author_id == self.author_id or (
            self.reply_to and self.reply_to.author_id == self.author_id
        ):
            return
        Notification.objects.create(
            role=self.post.author,
            type=NotificationType.POST_COMMENT,
            content={
                "post_id": self.post.id,
                "post_type": self.post.type,
                "comment_id": self.id,
                "comment_info": self.content[:50],
                "comment_author_name": self.author.name,
            },
        )


class PostCoinRecord(models.Model):
    post = models.ForeignKey(Post, models.CASCADE, related_name="coin_records")
    user = models.ForeignKey(User, models.CASCADE, related_name="post_coin_records")
    amount = models.IntegerField(default=0)
