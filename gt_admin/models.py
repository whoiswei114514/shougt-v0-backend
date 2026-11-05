from django.db import models

from gt_auth.models import User, Role
from gt_forum.models import Post, PostComment


class ReportContentTypeChoice(models.TextChoices):
    POST = "post", "帖子"
    COMMENT = "comment", "评论"
    ROLE = "role", "角色"
    USER = "user", "用户"

    @classmethod
    def get_model(cls, content_type):
        if content_type == cls.POST:
            return Post
        elif content_type == cls.COMMENT:
            return PostComment
        elif content_type == cls.ROLE:
            return Role
        return None


class ReportStatusChoice(models.IntegerChoices):
    REJECT = -1, "驳回举报"
    PENDING = 0, "等待处理"
    ACCEPT = 1, "举报已受理"


class Report(models.Model):
    user = models.ForeignKey(
        User, on_delete=models.SET_NULL, null=True, related_name="reports"
    )
    explanation = models.CharField(max_length=1000, blank=True, null=True)

    content_type = models.CharField(
        choices=ReportContentTypeChoice.choices,
        default=ReportContentTypeChoice.POST,
        max_length=31,
    )
    content_id = models.IntegerField()
    extra_content = models.JSONField(null=True, blank=True)

    status = models.IntegerField(
        choices=ReportStatusChoice.choices,
        default=ReportStatusChoice.PENDING,
    )
    operator = models.ForeignKey(
        User,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="operated_reports",
    )
    create_time = models.DateTimeField(auto_now_add=True)
    operate_time = models.DateTimeField(null=True)

    @classmethod
    def get_extra_content(cls, content_type, content_id):
        data = None
        if content_type == ReportContentTypeChoice.POST:
            post = Post.objects.get(id=content_id)
            data = {"post_type": post.type}
        return data


class AdminAuditLog(models.Model):
    actor_id = models.BigIntegerField(null=True, db_index=True)
    actor_name = models.CharField(max_length=150, default="")
    roles = models.JSONField(default=list)
    action = models.CharField(max_length=128)
    object_type = models.CharField(max_length=64, default="")
    object_id = models.CharField(max_length=128, default="")
    outcome = models.CharField(max_length=32, default="success")
    details = models.JSONField(default=dict)
    session_id = models.CharField(max_length=64, default="")
    watermark_id = models.CharField(max_length=64, default="")
    created_at = models.DateTimeField(auto_now_add=True, db_index=True)

    class Meta:
        ordering = ["-id"]
