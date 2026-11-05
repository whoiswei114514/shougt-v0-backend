from datetime import date
from django.db import models
from django.db import transaction
from math import isfinite
from rest_framework.exceptions import ValidationError
from gt_auth.models import User


class CoinRecordType(models.TextChoices):
    REGISTER = "register"
    SIGN = "sign"
    DAILY = "daily"
    ROLE = "role"
    POST = "post"
    ONE_TIME = "one_time"
    INVITE = "invite"
    DONATE = "donate"
    TRANSFER = "transfer"
    PUNISH = "punish"
    CHARGE = "charge"
    ADMIN = "admin"


class Coin(models.Model):
    total_confirmed = models.FloatField(default=0)
    confirmed_time = models.DateTimeField(auto_now_add=True)

    total = models.FloatField(default=0)

    invite_user = models.ForeignKey(
        User, on_delete=models.SET_NULL, related_name="invited_info", null=True
    )
    role_create_reward = models.BooleanField(default=False)
    role_change_reward = models.BooleanField(default=False)

    def update_total(self, change: float):
        if not isfinite(change):
            raise ValidationError("硬币变动必须为有限数值")
        type(self).objects.filter(pk=self.pk).update(total=models.F("total") + change)
        self.refresh_from_db(fields=["total"])

    @transaction.atomic
    def add_record(
        self, change: float, type: str, detail: str = "", allow_negative: bool = False
    ):
        if not isfinite(change):
            raise ValidationError("硬币变动必须为有限数值")
        current = Coin.objects.select_for_update().get(pk=self.pk)
        self.total = current.total
        if not allow_negative and change < 0 and self.total + change < 0:
            raise ValidationError("硬币数量不足")
        user = User.objects.get(coin=self)
        coin_record, created = CoinRecord.objects.get_or_create(
            user=user, date=date.today()
        )

        flag = coin_record.add_record(change, type, detail)

        if flag:
            self.update_total(change)
        return flag

    @property
    def record_today(self):
        if getattr(self, "_record_today", None) is None:
            self._record_today = CoinRecord.objects.get_or_create(
                user=self.user, date=date.today()
            )[0]
        return self._record_today


class CoinRecord(models.Model):
    user = models.ForeignKey(User, models.CASCADE, related_name="coin_records")
    date = models.DateField(auto_now_add=True)
    records = models.JSONField(null=True)

    sign = models.FloatField(null=True)
    post_reward = models.BooleanField(default=False)
    comment_reward = models.BooleanField(default=False)

    def add_record(self, change: float, type: str, detail: str = ""):
        CoinRecordRealtime.objects.create(
            record=self, type=type, detail=detail, change=change
        )
        if type == CoinRecordType.SIGN:
            self.sign = change
            self.save(update_fields=["sign"])

        return True


class CoinRecordRealtime(models.Model):
    record = models.ForeignKey(
        CoinRecord, models.CASCADE, related_name="realtime_records"
    )
    time = models.DateTimeField(auto_now_add=True)
    type = models.CharField(max_length=15, choices=CoinRecordType.choices)
    detail = models.CharField(max_length=100, null=True)
    change = models.FloatField()
