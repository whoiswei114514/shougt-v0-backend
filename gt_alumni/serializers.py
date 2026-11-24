from rest_framework import serializers
from gt_auth.models import User
from gt_auth.roles import assigned_roles
from .models import Alumni


class AlumniListSerializer(serializers.ModelSerializer):

    class Meta:
        model = Alumni
        fields = (
            "id",
            "name",
            "avatar",
            "gender",
            "year",
            "academic_background",
            "work_experience",
        )


class AlumniSerializer(serializers.ModelSerializer):
    has_permission = serializers.SerializerMethodField()

    def get_has_permission(self, obj):
        request = self.context.get("request")
        user = getattr(request, "user", None)
        if not user or not user.is_authenticated:
            return False
        if "global_reader" in assigned_roles(user.permission):
            return False
        return User.has_permission(user, "admin_alumni") or obj.user == user

    def validate_avatar(self, value):
        if value and not value.startswith(("https://", "http://")):
            raise serializers.ValidationError("头像地址协议不合法")
        return value

    def validate_year(self, value):
        if not 2015 < value < 2099:
            raise serializers.ValidationError('毕业年份不合法')
        return value

    class Meta:
        model = Alumni
        fields = ("id", "name", "avatar", "gender", "year",
                  "academic_background", "work_experience", "phone", "email",
                  "contact", "has_permission")
        read_only_fields = ("id", "has_permission")
