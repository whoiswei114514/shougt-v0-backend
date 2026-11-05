from random import randint, choice
from string import ascii_letters, digits
from datetime import timedelta
from django.db import models
from django.db import transaction
from uuid import uuid4
from django.utils import timezone
from rest_framework import status
from rest_framework.decorators import action
from rest_framework.exceptions import ValidationError
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.viewsets import ModelViewSet, GenericViewSet
from rest_framework.mixins import ListModelMixin, RetrieveModelMixin

from . import doge_api
from .models import Image, File, ExpireDaysChoice, Video
from .serializers import (
    ImageSerializer,
    FileUploadSerializer,
    FileSerializer,
    VideoSerializer,
    VideoDetailSerializer,
)
from .ali_oss_sign import sign_upload
from gt.permissions import HaveRoleOrReadOnly
from gt_auth.models import User


def random_string(length: int = 4) -> str:
    return "".join([choice(ascii_letters + digits) for _ in range(length)])


class ImageViewset(GenericViewSet, ListModelMixin):
    permission_classes = [IsAuthenticated]
    serializer_class = ImageSerializer
    filterset_fields = ["scene"]
    search_fields = ["^user__username", "user__real_name"]

    def get_queryset(self):
        user = self.request.user
        if User.has_permission(user, "admin_image"):
            queryset = Image.objects.all()
        else:
            queryset = Image.objects.filter(user=user)
        return queryset.order_by("-id")

    @transaction.atomic
    def create(self, request, *args, **kwargs):
        if isinstance(request.data, dict):
            _data = [request.data]
        else:
            _data = request.data
        if not isinstance(_data, list) or not 1 <= len(_data) <= 100:
            raise ValidationError("每次上传需包含 1 至 100 张图片")

        user = request.user
        User.objects.select_for_update().get(pk=user.pk)
        quota = {
            "image_max_size": user.quota.image_max_size,
            "image_24h_count_limit": user.quota.image_24h_count_limit,
            "image_24h_size_limit": user.quota.image_24h_size_limit,
        }

        count = 0
        data = []
        total_size = 0
        hashes = set()
        for item in _data:
            serializer = ImageSerializer(data=item)
            serializer.is_valid(raise_exception=True)
            md5 = serializer.validated_data["md5"]
            if md5 in hashes:
                raise ValidationError("同一批次不能重复提交图片")
            hashes.add(md5)
            if Image.objects.filter(md5=md5, is_banned=True).exists():
                raise ValidationError("此图片不可使用")
            image = Image.objects.filter(md5=md5, user=user).first()
            if image is not None:
                data.append(image)
                continue
            if serializer.validated_data["size"] > quota["image_max_size"]:
                raise ValidationError(
                    f"文件大小超过限制({int(quota['image_max_size'] / 1024 / 1024)}MB)"
                )
            data.append(serializer)
            count += 1
            total_size += serializer.validated_data["size"]

        time = timezone.now()
        recent_images = Image.objects.filter(
            user=user,
            create_time__gte=time - timedelta(days=1),
        )
        if recent_images.count() + count > quota["image_24h_count_limit"]:
            raise ValidationError(
                f"24小时内上传图片数量已达上限({quota['image_24h_count_limit']}张)"
            )
        elif (
            recent_images.aggregate(total_size=models.Sum("size"))["total_size"] or 0
        ) + total_size > quota["image_24h_size_limit"]:
            raise ValidationError(
                f"24小时内上传图片累计大小已达上限({quota['image_24h_size_limit']}MB)"
            )

        response_data = []
        for serializer in data:
            if type(serializer) == Image:
                response_data.append(
                    {"data": ImageSerializer(serializer).data, "upload_data": None}
                )
                continue
            key = (
                serializer.validated_data["scene"]
                + "/"
                + time.strftime("%Y-%m")
                + "/"
                + uuid4().hex
                + "."
                + serializer.validated_data["content_type"].split("/")[-1]
            )
            upload_data = sign_upload(
                key,
                serializer.validated_data["md5"],
                serializer.validated_data["size"],
                serializer.validated_data["content_type"],
                time,
            )
            serializer.save(user=user, key=key, create_time=time)
            response_data.append(
                {
                    "data": serializer.data,
                    "upload_data": upload_data,
                }
            )

        return Response({"msg": "ok", "data": response_data})


class FileViewset(GenericViewSet, ListModelMixin):
    permission_classes = [IsAuthenticated]
    serializer_class = FileSerializer

    def get_queryset(self):
        user = self.request.user
        if User.has_permission(user, "admin_file"):
            queryset = File.objects.all()
        else:
            queryset = File.objects.filter(user=user)
        return queryset.order_by("-id")

    def create(self, request, *args, **kwargs):
        if isinstance(request.data, dict):
            _data = [request.data]
        else:
            _data = request.data
        if not isinstance(_data, list) or not 1 <= len(_data) <= 100:
            raise ValidationError("每次上传需包含 1 至 100 个文件")

        user = request.user
        data = []

        for item in _data:
            serializer = FileUploadSerializer(data=item)
            serializer.is_valid(raise_exception=True)
            data.append(serializer)

        response_data = []
        file_items = []
        for serializer in data:
            if serializer.validated_data["expire_days"] not in [
                choice[0] for choice in ExpireDaysChoice.choices
            ]:
                raise ValidationError("过期时间不是合法选项")
            expire_days = serializer.validated_data["expire_days"]
            serializer.validated_data.pop("expire_days")
            serializer.save(user=user)
            key = (
                f"expire_{expire_days}"
                + "/"
                + str(serializer.instance.id)
                + "/"
                + serializer.validated_data["name"]
            )
            serializer.instance.key = key
            serializer.instance.save(update_fields=["key"])
            _data = serializer.data
            _data["key"] = key
            response_data.append(_data)
            file_items.append(serializer.instance)

        upload_data = doge_api.get_upload_data(file_items)

        return Response(
            {"msg": "ok", "data": response_data, "upload_data": upload_data}
        )



class VideoViewset(GenericViewSet, ListModelMixin, RetrieveModelMixin):
    permission_classes = [IsAuthenticated]

    def get_serializer_class(self):
        if self.action == "retrieve":
            return VideoDetailSerializer
        return VideoSerializer

    def get_queryset(self):
        user = self.request.user
        if User.has_permission(user, "admin_image"):
            queryset = Video.objects.all()
        elif self.action == "retrieve":
            from gt_forum.visibility import visible_posts
            visible_ids = visible_posts(user, self.request.role).exclude(video_id=None).values("video_id")
            queryset = Video.objects.filter(models.Q(user=user) | models.Q(is_active=True, pk__in=visible_ids))
        else:
            queryset = Video.objects.filter(user=user)
        return queryset.order_by("-id")

    def create(self, request, *args, **kwargs):
        user = request.user

        if not isinstance(request.data.get("content_type"), str) or not request.data["content_type"].startswith("video/"):
            raise ValidationError("不支持的文件类型")
        else:
            request.data.pop("content_type")

        serializer = VideoSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        quota = {
            "video_max_size": user.quota.video_max_size,
            "video_24h_count_limit": user.quota.video_24h_count_limit,
            "video_24h_size_limit": user.quota.video_24h_size_limit,
        }

        start_time = timezone.now() - timedelta(days=1)
        videos_24h = Video.objects.filter(user=user, create_time__gte=start_time)
        if videos_24h.count() >= quota["video_24h_count_limit"]:
            raise ValidationError("24小时内上传视频数量超出限制")
        if serializer.validated_data["size"] > quota["video_max_size"]:
            raise ValidationError("单个视频大小超出限制")
        total_size = sum(v.size for v in videos_24h)
        total_size += serializer.validated_data["size"]
        if total_size > quota["video_24h_size_limit"]:
            raise ValidationError("24小时内上传视频总大小超出限制")

        time = timezone.now()
        serializer.save(user=user, create_time=time)

        upload_data = doge_api.get_video_upload_data(serializer.instance)

        serializer.instance.did = upload_data["VodUploadInfo"]["did"]
        serializer.instance.save(update_fields=["did"])

        response_data = {
            "data": serializer.data,
            "upload_data": upload_data,
        }

        return Response({"msg": "ok", "data": response_data})

    @action(
        detail=False,
        methods=["get"],
        url_path="dogecloud_callback",
        permission_classes=[],
    )
    def dogecloud_callback(self, request, *args, **kwargs):
        msg = request.query_params.get("msg")
        vcode = request.query_params.get("vcode")
        callback_string = request.query_params.get("callbackString")

        try:
            video = Video.objects.get(uuid=callback_string)
            if vcode:
                video.vcode = vcode
            if msg == "transcode":
                video.is_active = True
            video.save(update_fields=["vcode", "is_active"])
        except Video.DoesNotExist:
            ...

        return Response("DogeCloud Callback Success")
