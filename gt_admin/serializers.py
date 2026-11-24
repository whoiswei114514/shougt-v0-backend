from math import isfinite
from django.utils import timezone

from rest_framework import serializers

from gt.validators import SQLITE_MAX_INT
from .models import Report, ReportContentTypeChoice
from ._models import ReviewStatusChoice
from gt_auth.serializers import UserBriefSerializer, PrivateUserReferenceSerializer
from gt_auth.models import Role, User
from gt_coin.models import CoinRecordType


class ReviewSerializer(serializers.Serializer):
    status = serializers.ChoiceField(choices=ReviewStatusChoice.choices)
    message = serializers.CharField(required=False, allow_blank=True, default="")

    @property
    def review_data(self):
        return {
            "reviewer_type": "admin",
            "reviewer": self.context["request"].user.id,
            "review_time": timezone.now().isoformat(),
            "message": self.validated_data.get("message", ""),
            "status": self.validated_data["status"],
        }


class ReportSerializer(serializers.ModelSerializer):
    user = UserBriefSerializer(read_only=True)
    operator = PrivateUserReferenceSerializer(read_only=True)

    def to_representation(self, instance):
        data = super().to_representation(instance)
        request = self.context.get("request")
        actor = request.user if request else None
        if not (actor and actor.is_authenticated and User.has_permission(actor, "admin_report")):
            data["operator"] = None
        return data

    class Meta:
        model = Report
        fields = "__all__"
        read_only_fields = (
            "id",
            "user",
            "explanation",
            "content_type",
            "content_id",
            "extra_content",
            "operator",
            "create_time",
            "operate_time",
        )


class ReportCreateSerializer(serializers.ModelSerializer):
    content_id = serializers.IntegerField(min_value=1, max_value=SQLITE_MAX_INT)

    class Meta:
        model = Report
        fields = ["content_type", "content_id", "explanation"]


class AddCoinRecordSerializer(serializers.Serializer):
    change = serializers.FloatField(min_value=-1_000_000_000, max_value=1_000_000_000)
    detail = serializers.CharField(required=False, allow_blank=True, default="")
    type = serializers.ChoiceField(choices=CoinRecordType.choices)

    def validate_change(self, value):
        if not isfinite(value):
            raise serializers.ValidationError("硬币变动必须为有限数值")
        return value
