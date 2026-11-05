from uuid import uuid4

from django.db import models

from gt_auth.models import User


class ImageSceneChoice(models.TextChoices):
    DEFAULT = "default", "默认"
    POST = "post", "帖子"
    AVATAR = "avatar", "头像"
    ALUMNI_AVATAR = "alumni_avatar", "校友头像"


def uuid():
    return uuid4().hex.replace("-", "")


class Image(models.Model):
    user = models.ForeignKey(User, on_delete=models.SET_NULL, null=True)
    name = models.CharField(max_length=255)
    key = models.CharField(max_length=511)
    md5 = models.CharField(max_length=32)
    content_type = models.CharField(max_length=255)
    size = models.IntegerField()
    create_time = models.DateTimeField()
    scene = models.CharField(
        max_length=31,
        choices=ImageSceneChoice.choices,
        default=ImageSceneChoice.DEFAULT,
    )

    is_banned = models.BooleanField(default=False)

    class Meta:
        constraints = [models.UniqueConstraint(fields=["user", "md5"], name="unique_image_hash_per_user")]


class FileStorageChoice(models.TextChoices):
    DOGECLOUD = "dogecloud", "多吉云"


class File(models.Model):
    user = models.ForeignKey(User, on_delete=models.SET_NULL, null=True)
    name = models.CharField(max_length=255)
    key = models.CharField(max_length=511, unique=True, default=uuid)
    content_type = models.CharField(max_length=255)
    storage = models.CharField(
        max_length=31,
        choices=FileStorageChoice.choices,
        default=FileStorageChoice.DOGECLOUD,
    )
    size = models.IntegerField()
    create_time = models.DateTimeField(auto_now_add=True)
    verified = models.BooleanField(default=False)


class ExpireDaysChoice(models.IntegerChoices):
    DAY_1 = 1
    DAY_3 = 3
    DAY_7 = 7
    DAY_15 = 15


class Video(models.Model):
    uuid = models.UUIDField(default=uuid)
    user = models.ForeignKey(User, on_delete=models.SET_NULL, null=True)
    name = models.CharField(max_length=255)
    size = models.IntegerField()
    create_time = models.DateTimeField(auto_now_add=True)
    did = models.CharField(max_length=100, null=True)
    vcode = models.CharField(max_length=100, null=True)
    is_active = models.BooleanField(default=False)
