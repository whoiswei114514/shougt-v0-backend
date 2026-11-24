from rest_framework import serializers
from .models import Coin, CoinRecord, CoinRecordRealtime
from rest_framework.exceptions import ValidationError


class CoinSerializer(serializers.ModelSerializer):
    class Meta:
        model = Coin
        fields = "__all__"


class CoinRecordItemSerializer(serializers.ModelSerializer):
    class Meta:
        model = CoinRecordRealtime
        exclude = ("id", "record")


class CoinRecordSerializer(serializers.ModelSerializer):
    records = serializers.SerializerMethodField()

    def get_records(self, obj):
        if obj.records:
            return obj.records
        records = CoinRecordRealtime.objects.filter(record=obj)
        return CoinRecordItemSerializer(records, many=True).data

    class Meta:
        model = CoinRecord
        fields = "__all__"


class CoinTransferSerializer(serializers.Serializer):
    to_user_id = serializers.IntegerField(min_value=1, max_value=9223372036854775807)
    amount = serializers.IntegerField(min_value=1, max_value=1000000)


class DonateCoinSerializer(serializers.Serializer):
    amount = serializers.IntegerField(min_value=1)
    post_id = serializers.IntegerField(required=False)
    role_id = serializers.IntegerField(required=False)
