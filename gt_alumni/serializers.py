from rest_framework import serializers
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
        user = self.context.get("request").user
        if not user:
            return False
        return user.has_permission(user, "admin_alumni") or obj.user == user

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
