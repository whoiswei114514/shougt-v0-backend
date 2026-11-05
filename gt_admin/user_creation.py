"""Ordinary account creation from the user list; permissions are never input fields."""
from django.contrib.auth.password_validation import validate_password
from django.db import IntegrityError, transaction
from rest_framework import serializers
from rest_framework.exceptions import ValidationError

from gt_auth.education import normalize_education_email, education_identity, education_student_id
from gt_auth.models import User, Role, Permission, Privacy, Quota
from gt_auth.serializers import UserDetailReadSerializer
from gt_coin.models import Coin, CoinRecordType
from gt_coin import amount as coin_amount
from .audit import record


class CreateUserSerializer(serializers.Serializer):
    username = serializers.CharField(max_length=150)
    email = serializers.CharField(max_length=254)
    password = serializers.CharField(max_length=1024, trim_whitespace=False, write_only=True)
    real_name = serializers.CharField(max_length=40, allow_blank=True, required=False, default="")

    def to_internal_value(self, data):
        unknown = set(data) - set(self.fields)
        if unknown:
            raise ValidationError({"non_field_errors": ["创建用户不接受权限、认证状态或其他额外字段"]})
        return super().to_internal_value(data)

    def validate_username(self, value):
        for validator in User._meta.get_field("username").validators:
            validator(value)
        if User.objects.filter(username=value).exists():
            raise ValidationError("该用户名已存在")
        return value

    def validate_email(self, value):
        value = normalize_education_email(value)
        if User.objects.filter(email__iexact=value, email_verified_at__isnull=False).exists():
            raise ValidationError("该教育邮箱已绑定其他账号")
        return value


    def validate(self, data):
        validate_password(data["password"], User(username=data["username"], email=data["email"]))
        education_student_id(data["email"])
        return data


def create_user(request):
    serializer = CreateUserSerializer(data=request.data)
    serializer.is_valid(raise_exception=True)
    data = serializer.validated_data
    email = data["email"]
    try:
        with transaction.atomic():
            identity, school = education_identity(email)
            user = User.objects.create_user(username=data["username"], password=data["password"], email=email,
                real_name=data["real_name"], student_id=education_student_id(email), email_verified_at=None,
                identity=identity, school=school, permission=Permission.objects.create(),
                quota=Quota.objects.create(), privacy=Privacy.objects.create(), coin=Coin.objects.create())
            Role.generate_default_role(user)
            user.coin.add_record(coin_amount.REGISTER, CoinRecordType.REGISTER, detail="管理员创建账号")
            record(request.user, "create_user", object_type="user", object_id=user.pk,
                   details={"username": user.username, "identity": identity, "school": school,
                            "student_id": user.student_id, "email_verified": False, "creation_method": "administrator"},
                   session=request.security_session)
    except IntegrityError as exc:
        raise ValidationError("用户名或教育邮箱已被使用") from exc
    return {"msg": "用户已创建", "data": UserDetailReadSerializer(user).data}
