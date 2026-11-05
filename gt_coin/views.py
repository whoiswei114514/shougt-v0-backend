import random
from math import cos, pi
from datetime import date

from django.http import Http404
from django.db import transaction
from django.shortcuts import get_object_or_404
from rest_framework.decorators import action
from rest_framework.mixins import RetrieveModelMixin
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.viewsets import GenericViewSet

from .models import Coin, CoinRecord, CoinRecordType
from .serializers import CoinRecordSerializer, CoinTransferSerializer, CoinSerializer
from gt_auth.models import User
from . import amount as coin_amount


def random_sign_amount():
    x = random.random()
    m, n, p = 0.2, 0.55, 0.9
    y = 0
    if x <= m:
        y = 2 / (1 + x / m) + 1
    elif x <= n:
        y = (x - m) / (m - n) + 2
    elif x <= p:
        y = cos(pi / 2 * (x - n) / (p - n))
    else:
        y = 0.5 * (cos(pi / 2 * (x - p) / (1 - p)) - 1)
    if -0.01 < y < 0.01:
        y = random.choice([-0.5, 1, 3])
    return round(y, 2)


class CoinViewset(GenericViewSet, RetrieveModelMixin):
    permission_classes = [IsAuthenticated]
    serializer_class = CoinRecordSerializer

    def get_queryset(self):
        user = self.request.user
        queryset = CoinRecord.objects.filter(user=user)
        return queryset.order_by("-id")

    def list(self, request, *args, **kwargs):
        queryset = self.get_queryset()
        data = [str(obj.date) for obj in queryset]
        return Response({"msg": "ok", "data": data})

    def get_object(self):
        queryset = self.get_queryset()
        pk = self.kwargs.get("pk")
        _date = str(pk)
        obj = queryset.filter(date=_date).first()
        if not obj:
            raise Http404
        return obj

    @action(detail=False, methods=["get"], url_path="detail")
    def coin_detail(self, request):
        return Response(CoinSerializer(request.user.coin).data)

    @action(detail=False, methods=["get", "post"], url_path="sign")
    @transaction.atomic
    def sign(self, request):
        user = request.user
        if request.method == "GET":
            coin_record = CoinRecord.objects.filter(
                user=user, date=date.today()
            ).first()
            return Response(
                {
                    "msg": "ok",
                    "signed": coin_record is not None and bool(coin_record.sign),
                    "date": coin_record and coin_record.date,
                }
            )

        Coin.objects.select_for_update().get(pk=user.coin_id)
        coin_record, _created = CoinRecord.objects.get_or_create(
            user=user, date=date.today()
        )
        change = None
        if not coin_record.sign:
            change = random_sign_amount()
            coin_record.add_record(change, CoinRecordType.SIGN)
            user.coin.update_total(change)
        else:
            change = coin_record.sign
        return Response(
            {
                "msg": "ok",
                "change": f"{change:.2f}" if change is not None else None,
                "date": coin_record.date,
            }
        )

    @action(detail=False, methods=["post"], url_path="transfer")
    @transaction.atomic
    def transfer(self, request):
        serializer = CoinTransferSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        to_user_id = serializer.validated_data["to_user_id"]
        user: User = request.user
        from gt_auth.privacy import discoverable_users
        to_user = get_object_or_404(discoverable_users(user).exclude(pk=user.pk), id=to_user_id)
        # Lock both balances in a stable order, including opposing transfers.
        list(Coin.objects.select_for_update().filter(pk__in=[user.coin_id, to_user.coin_id]).order_by("pk"))

        amount = serializer.validated_data["amount"]

        user.coin.add_record(
            -amount,
            CoinRecordType.TRANSFER,
            f"向用户 #{to_user.pk} 转账",
        )
        to_user.coin.add_record(
            amount * coin_amount.TRANSFER_RATE,
            CoinRecordType.TRANSFER,
            f"收到用户 #{user.pk} 转账",
        )
        return Response({"msg": "ok"})
