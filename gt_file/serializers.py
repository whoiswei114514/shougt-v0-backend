from rest_framework import serializers
from .models import Image, File, Video
from gt_auth.serializers import RoleBriefSerializer, UserBriefSerializer
from .doge_api import generate_playtoken


class ImageViewSerializer(serializers.ModelSerializer):
    class Meta:
        model = Image
        fields = read_only_fields = ("id", "key")


class ImageSerializer(serializers.ModelSerializer):
    user = UserBriefSerializer(read_only=True)
    md5 = serializers.RegexField(r"^[0-9a-fA-F]{32}$")
    size = serializers.IntegerField(min_value=1)
    content_type = serializers.ChoiceField(choices=[
        "image/jpeg", "image/png", "image/webp", "image/gif", "image/avif", "image/bmp",
        "image/tiff", "image/x-icon", "image/vnd.microsoft.icon", "image/heic", "image/heif",
    ])

    def validate_md5(self, value):
        return value.lower()

    class Meta:
        model = Image
        fields = "__all__"
        read_only_fields = ("id", "key", "create_time", "is_banned", "user")


class FileUploadSerializer(serializers.ModelSerializer):
    expire_days = serializers.IntegerField(default=0)
    size = serializers.IntegerField(min_value=1)

    def validate_name(self, value):
        if value in {".", ".."} or any(character in value for character in "/\\\r\n\x00"):
            raise serializers.ValidationError("文件名不能包含路径或控制字符")
        return value

    class Meta:
        model = File
        fields = ("id", "name", "content_type", "storage", "size", "expire_days")
        read_only_fields = ("id",)


class FileSerializer(serializers.ModelSerializer):
    class Meta:
        model = File
        fields = read_only_fields = (
            "id",
            "name",
            "content_type",
            "storage",
            "size",
            "create_time",
            "verified",
        )


class VideoSerializer(serializers.ModelSerializer):
    size = serializers.IntegerField(min_value=1)

    class Meta:
        model = Video
        fields = (
            "id",
            "name",
            "size",
            "create_time",
            "did",
            "vcode",
            "is_active",
        )
        read_only_fields = ("id", "did", "vcode", "is_active", "create_time")


class VideoDetailSerializer(serializers.ModelSerializer):
    playtoken = serializers.SerializerMethodField()

    def get_playtoken(self, obj):
        if not all([obj.did, obj.vcode, obj.is_active]):
            return None
        return generate_playtoken(obj.vcode)

    class Meta:
        model = Video
        fields = (
            "id",
            "name",
            "size",
            "create_time",
            "did",
            "vcode",
            "is_active",
            "playtoken",
        )
        read_only_fields = (
            "id",
            "did",
            "vcode",
            "is_active",
            "create_time",
            "playtoken",
        )
