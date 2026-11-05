from django.utils import timezone

from rest_framework import serializers

from .models import Report, ReportContentTypeChoice
from ._models import ReviewStatusChoice
from gt_auth.serializers import UserBriefSerializer, PrivateUserReferenceSerializer
from gt_auth.models import Role
from gt_coin.models import CoinRecordType


class ReviewSerializer(serializers.Serializer):
    status = serializers.ChoiceField(choices=ReviewStatusChoice.choices)
    message = serializers.CharField(required=False, allow_blank=True)

    @property
    def review_data(self):
        return {
            "reviewer_type": "admin",
            "reviewer": self.context["request"].user.id,
            "review_time": timezone.now().isoformat(),
            "message": self.validated_data["message"],
            "status": self.validated_data["status"],
        }


class ReportSerializer(serializers.ModelSerializer):
    user = UserBriefSerializer(read_only=True)
    operator = PrivateUserReferenceSerializer(read_only=True)

    class Meta:
        model = Report
        fields = "__all__"


class ReportCreateSerializer(serializers.ModelSerializer):
    class Meta:
        model = Report
        fields = ["content_type", "content_id", "explanation"]


class AddCoinRecordSerializer(serializers.Serializer):
    change = serializers.FloatField()
    detail = serializers.CharField(required=False, allow_blank=True)
    type = serializers.ChoiceField(choices=CoinRecordType.choices)
