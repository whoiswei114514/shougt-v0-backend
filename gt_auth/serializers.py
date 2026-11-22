from rest_framework import serializers
from rest_framework.exceptions import ValidationError
from .models import (
    User,
    Role,
    Quota,
    Permission,
    Privacy,
    Notification,
    Follow,
    TrustedUser,
    resolve_ban_state,
)
from .privacy import discoverable_users, invitable_users
from .roles import ROLE_LABELS, effective_roles, visible_badges
from gt_forum.tasks import review_with_aliyun
from gt_admin._models import ReviewStatusChoice
from gt_coin.models import CoinRecordType
import gt_coin.amount as coin_amount


class UserDetailReadSerializer(serializers.ModelSerializer):
    badges = serializers.SerializerMethodField()
    is_active = serializers.SerializerMethodField()
    banned_until = serializers.SerializerMethodField()
    permanently_banned = serializers.SerializerMethodField()

    def get_badges(self, obj):
        return visible_badges(obj.permission)

    def get_is_active(self, obj):
        return obj.is_currently_active

    def get_banned_until(self, obj):
        return serializers.DateTimeField().to_representation(obj.active_banned_until) if obj.active_banned_until else None

    def get_permanently_banned(self, obj):
        return not obj.is_active

    class Meta:
        model = User
        fields = read_only_fields = (
            "id",
            "username",
            "real_name",
            "student_id",
            "school",
            "date_joined",
            "identity",
            "is_active",
            "banned_until",
            "permanently_banned",
            "email",
            "email_verified_at",
            "real_name_verified_at",
            "advanced_verified_at",
            "primary_role_id",
            "badges",
        )


class UserBriefSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = read_only_fields = ("id", "username", "real_name", "student_id")


class PrivateUserReferenceSerializer(UserBriefSerializer):
    """Existing references are not permission to disclose an account's identity."""
    def to_representation(self, instance):
        request = self.context.get("request")
        actor = request.user if request else self.context.get("user")
        if actor and actor.is_authenticated:
            admin_key = f"_is_admin_role_{actor.pk}"
            if admin_key not in self.context:
                self.context[admin_key] = User.has_permission(actor, "admin_role")
            if self.context[admin_key]:
                return super().to_representation(instance)
            cache_key = f"_discoverable_ids_{actor.pk}"
            allowed_ids = self.context.get(cache_key)
            if allowed_ids is None:
                allowed_ids = set(discoverable_users(actor).values_list("id", flat=True))
                self.context[cache_key] = allowed_ids
            if instance.pk in allowed_ids:
                return super().to_representation(instance)
        return {"id": instance.pk, "username": "", "real_name": "", "student_id": None}


class UserCreateSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ["username", "real_name", "password", "identity", "school", "student_id"]


class IsRoleOwnerField(serializers.ReadOnlyField):
    def to_representation(self, value):
        user = self.context.get("user") or (
            self.context.get("request") and self.context["request"].user
        )
        if not user or not user.is_authenticated:
            return False
        return value.is_owner(user)


class IsRoleAdminField(serializers.ReadOnlyField):
    def to_representation(self, value):
        user = self.context.get("user") or (
            self.context.get("request") and self.context["request"].user
        )
        if not user or not user.is_authenticated:
            return False
        return value.is_role_admin(user)


class QuotaSerializer(serializers.ModelSerializer):
    class Meta:
        model = Quota
        exclude = ("id",)


class PermissionSerializer(serializers.ModelSerializer):
    def to_representation(self, instance):
        effective = effective_roles(instance)
        return {key: key in effective for key in ROLE_LABELS}
    class Meta:
        model = Permission
        exclude = ("id",)


class PrivacySerializer(serializers.ModelSerializer):
    trusted_users = serializers.JSONField(write_only=True, required=False)

    class Meta:
        model = Privacy
        exclude = ("id",)

    def validate_trusted_users(self, value):
        if not isinstance(value, list):
            raise serializers.ValidationError("trusted_users应为列表")
        for user_id in value:
            if type(user_id) is not int or user_id <= 0:
                raise serializers.ValidationError("trusted_users的项应为正整数")
        if len(value) > 100 or len(value) != len(set(value)):
            raise serializers.ValidationError("信任列表不能重复，最多添加100位用户")
        actor = self.context["request"].user
        existing = set(TrustedUser.objects.filter(user=actor).values_list("trusted_user_id", flat=True))
        additions = set(value) - existing
        if discoverable_users(actor).filter(pk__in=additions).count() != len(additions):
            raise serializers.ValidationError("部分用户不可选择，请通过可见用户列表添加")
        return value


class RoleIdField(serializers.ReadOnlyField):
    def to_representation(self, obj):
        if obj.is_private and not self.context.get("safe"):
            user = None
            if self.context.get("user"):
                user = self.context.get("user")
            elif self.context.get("request"):
                user = self.context.get("request").user
            if not user or not obj.is_member(user):
                return None
        return obj.id


class RoleBriefSelfSerializer(serializers.ModelSerializer):
    badges = serializers.ReadOnlyField()
    is_primary = serializers.ReadOnlyField()
    is_active = serializers.SerializerMethodField()
    banned_until = serializers.SerializerMethodField()
    unread_notification_count = serializers.SerializerMethodField()

    def get_is_active(self, obj):
        return obj.is_currently_active

    def get_banned_until(self, obj):
        return serializers.DateTimeField().to_representation(obj.active_banned_until) if obj.active_banned_until else None

    def get_unread_notification_count(self, obj):
        if hasattr(obj, "_unread_count"):
            return obj._unread_count
        return Notification.objects.filter(role=obj, is_read=False).count()

    class Meta:
        model = Role
        fields = read_only_fields = (
            "id",
            "name",
            "avatar",
            "verify",
            "badges",
            "is_private",
            "is_primary",
            "is_active",
            "banned_until",
            "unread_notification_count",
        )


class RoleBriefSerializer(serializers.ModelSerializer):
    badges = serializers.ReadOnlyField()
    id = RoleIdField(source="*")

    class Meta:
        model = Role
        fields = read_only_fields = ("id", "name", "avatar", "verify", "badges")


class RoleSerializer(serializers.ModelSerializer):
    badges = serializers.ReadOnlyField()
    id = RoleIdField(source="*")
    user_info = serializers.SerializerMethodField()

    def get_user_info(self, obj):
        if obj.show_user_info:
            return UserBriefSerializer(obj.members.get(is_owner=True).user).data

    class Meta:
        model = Role
        fields = read_only_fields = (
            "id",
            "name",
            "avatar",
            "verify",
            "badges",
            "user_info",
            "description",
            "following_count",
            "follower_count",
        )


class RoleAdminSerializer(serializers.ModelSerializer):
    badges = serializers.ReadOnlyField()
    user_info = serializers.SerializerMethodField()
    is_active = serializers.BooleanField(required=False)
    banned_until = serializers.DateTimeField(required=False, allow_null=True)
    duration_minutes = serializers.IntegerField(write_only=True, required=False, allow_null=True)
    ban_duration_minutes = serializers.IntegerField(write_only=True, required=False, allow_null=True)
    permanently_banned = serializers.BooleanField(required=False)

    def get_user_info(self, obj):
        return UserBriefSerializer(obj.members.get(is_owner=True).user).data

    def validate_verify(self, value):
        if value and any(label in value for label in ROLE_LABELS.values()):
            raise ValidationError("管理认证由账号权限自动生成，不能手动填写")
        return value

    def validate(self, attrs):
        attrs = super().validate(attrs)
        ban_keys = {"is_active", "banned_until", "duration_minutes", "ban_duration_minutes", "permanently_banned"}
        if ban_keys & set(attrs):
            resolved_active, resolved_until = resolve_ban_state(attrs)
            attrs["is_active"] = resolved_active
            attrs["banned_until"] = resolved_until
        attrs.pop("duration_minutes", None)
        attrs.pop("ban_duration_minutes", None)
        attrs.pop("permanently_banned", None)
        return attrs

    def to_representation(self, instance):
        data = super().to_representation(instance)
        data["is_active"] = instance.is_currently_active
        data["banned_until"] = serializers.DateTimeField().to_representation(instance.active_banned_until) if instance.active_banned_until else None
        data["permanently_banned"] = not instance.is_active
        return data

    class Meta:
        model = Role
        fields = (
            "id",
            "name",
            "avatar",
            "verify",
            "badges",
            "user_info",
            "description",
            "show_like",
            "is_active",
            "banned_until",
            "duration_minutes",
            "ban_duration_minutes",
            "permanently_banned",
            "editable",
            "following_count",
            "follower_count",
        )
        read_only_fields = (
            "id",
            "name",
            "avatar",
            "description",
            "following_count",
            "follower_count",
        )


class RoleDetailSerializer(serializers.ModelSerializer):
    badges = serializers.ReadOnlyField()
    id = RoleIdField(source="*")
    user_info = serializers.SerializerMethodField()
    is_owner = IsRoleOwnerField(source="*")
    is_admin = IsRoleAdminField(source="*")
    followed = serializers.SerializerMethodField()

    def get_followed(self, obj):
        request = self.context.get("request")
        if request is None:
            return False
        role = getattr(request, "role", None)
        if role is None:
            return False
        return Follow.objects.filter(follower=role, following=obj).exists()

    def get_user_info(self, obj):
        if obj.show_user_info:
            return UserBriefSerializer(obj.members.get(is_owner=True).user).data

    class Meta:
        model = Role
        fields = (
            "id",
            "name",
            "avatar",
            "description",
            "is_private",
            "is_shared",
            "show_user_info",
            "user_info",
            "show_like",
            "editable",
            "verify",
            "badges",
            "is_owner",
            "is_admin",
            "followed",
            "following_count",
            "follower_count",
        )


class RoleFullSerializer(serializers.ModelSerializer):
    badges = serializers.ReadOnlyField()
    is_primary = serializers.ReadOnlyField()
    # 包含敏感信息，只应展示给角色成员；唯一可能用于编辑的Role Serializer

    is_owner = IsRoleOwnerField(source="*")
    is_admin = IsRoleAdminField(source="*")
    is_active = serializers.SerializerMethodField()
    banned_until = serializers.SerializerMethodField()
    permanently_banned = serializers.SerializerMethodField()
    user_info = serializers.SerializerMethodField()
    members = serializers.SerializerMethodField()
    admins = serializers.SerializerMethodField()
    followed = serializers.SerializerMethodField()

    def get_is_active(self, obj):
        return obj.is_currently_active

    def get_banned_until(self, obj):
        return serializers.DateTimeField().to_representation(obj.active_banned_until) if obj.active_banned_until else None

    def get_permanently_banned(self, obj):
        return not obj.is_active

    def get_followed(self, obj):
        request = self.context.get("request")
        if request is None:
            return False
        role = getattr(request, "role", None)
        if role is None:
            return False
        return Follow.objects.filter(follower=role, following=obj).exists()

    def get_user_info(self, obj):
        owner = obj.members.get(is_owner=True).user
        if obj.show_user_info:
            return UserBriefSerializer(owner).data
        return PrivateUserReferenceSerializer(owner, context=self.context).data

    def get_members(self, obj):
        members = [
            member.user
            for member in obj.members.filter(is_owner=False)
            .select_related("user")
            .order_by("-is_admin", "id")
        ]
        return PrivateUserReferenceSerializer(members, many=True, context=self.context).data

    def get_admins(self, obj):
        admins = [
            member.user
            for member in obj.members.filter(is_owner=False, is_admin=True)
            .select_related("user")
            .order_by("id")
        ]
        return PrivateUserReferenceSerializer(admins, many=True, context=self.context).data

    members_id = serializers.JSONField(write_only=True, required=False)
    admins_id = serializers.JSONField(write_only=True, required=False)

    def validate(self, attrs):
        if self.instance and self.instance.is_primary:
            if attrs.get("is_private") or attrs.get("is_shared") or attrs.get("members_id") or attrs.get("admins_id"):
                raise ValidationError("注册主角色用于个人身份和管理认证，不能设为匿名或共享角色")
        target_shared = attrs.get("is_shared", self.instance.is_shared if self.instance else False)
        if (attrs.get("members_id") or attrs.get("admins_id")) and not target_shared:
            raise ValidationError("请先将角色设为共享角色")
        if "admins_id" in attrs:
            actor = self.context["user"]
            owner_id = self.instance.owner.pk if self.instance else actor.pk
            cleaned_admins = [uid for uid in attrs["admins_id"] if uid != owner_id]
            if "members_id" in attrs:
                valid_members = set(attrs["members_id"])
            elif self.instance:
                valid_members = set(self.instance.members.filter(is_owner=False).values_list("user_id", flat=True))
            else:
                valid_members = set()
            if set(cleaned_admins) - valid_members:
                raise ValidationError("角色管理员必须是该共享角色的成员")
            attrs["admins_id"] = cleaned_admins
        return attrs

    def validate_members_id(self, value):
        if not isinstance(value, list):
            raise serializers.ValidationError("members_id应为列表")
        for user_id in value:
            if type(user_id) is not int or user_id <= 0:
                raise serializers.ValidationError("members_id的项应为正整数")
        if len(value) != len(set(value)):
            raise serializers.ValidationError("角色成员不能重复")
        actor = self.context["user"]
        owner_user = self.instance.owner if self.instance else actor
        role_max_members = owner_user.quota.role_max_members
        if len(value) > role_max_members:
            raise serializers.ValidationError(
                f"角色成员数不能超过{role_max_members}，请联系管理员提高配额"
            )
        existing = set(self.instance.members.values_list("user_id", flat=True)) if self.instance else set()
        additions = set(value) - existing - {owner_user.pk, actor.pk}
        if invitable_users(actor).filter(pk__in=additions).count() != len(additions):
            raise serializers.ValidationError("部分用户未允许加入共享角色")
        return value

    def validate_admins_id(self, value):
        if not isinstance(value, list):
            raise serializers.ValidationError("admins_id应为列表")
        for user_id in value:
            if type(user_id) is not int or user_id <= 0:
                raise serializers.ValidationError("admins_id的项应为正整数")
        if len(value) != len(set(value)):
            raise serializers.ValidationError("角色管理员不能重复")
        actor = self.context["user"]
        if self.instance and not self.instance.is_owner(actor):
            raise serializers.ValidationError("仅角色所有者可设置角色管理员")
        return value

    def is_valid(self, raise_exception=False):
        res = super().is_valid(raise_exception=raise_exception)
        if self.context.get("member_only_update"):
            return res
        user = self.context["user"]

        if User.has_permission(user, "no_review"):
            return res

        instance = getattr(self, "instance", None)

        _name = self.validated_data.get("name", "")
        _description = self.validated_data.get("description", "")

        queryset = Role.objects.filter(name=_name)
        if instance:
            queryset = queryset.exclude(id=instance.id)
        if queryset.exists():
            raise ValidationError("角色名已被使用")

        need_review = instance is None
        if _name and (instance is None or _name != instance.name):
            need_review = True
        if _description and (instance is None or _description != instance.description):
            need_review = True

        if need_review:
            review_text = _name + "\n" + _description

            if instance is None or _name != instance.name:
                user.coin.add_record(
                    coin_amount.ROLE_REVIEW,
                    CoinRecordType.ROLE,
                    "修改角色名称" if instance else "创建角色",
                    allow_negative=bool(
                        not instance and not user.coin.role_create_reward
                    ),
                )
            review_res = review_with_aliyun(review_text, "nickname_detection")
            if review_res["status"] != ReviewStatusChoice.ACCEPTED:
                user.coin.add_record(
                    coin_amount.ROLE_VIOLATION,
                    CoinRecordType.PUNISH,
                    "角色信息违规",
                )
                raise ValidationError(f"角色信息违规：{review_res['message']}")

        _avatar = self.validated_data.get("avatar", "")
        if instance and instance.avatar and _avatar and _avatar != instance.avatar:
            user.coin.add_record(
                coin_amount.ROLE_AVATAR, CoinRecordType.ROLE, "修改角色头像"
            )

        return res

    def create(self, validated_data):
        validated_data.pop("members_id", None)
        validated_data.pop("admins_id", None)
        res = super().create(validated_data)
        user = self.context["user"]
        coin = user.coin
        if not coin.role_create_reward:
            coin.add_record(
                coin_amount.ROLE_CREATE_REWARD,
                CoinRecordType.ONE_TIME,
                "首次创建角色奖励",
            )
            coin.role_create_reward = True
            coin.save(update_fields=["role_create_reward"])
        return res

    def save(self, **kwargs):
        if self.context.get("member_only_update"):
            return self.instance
        user = self.context["user"]
        coin = user.coin
        if not coin.role_change_reward:
            coin.add_record(
                coin_amount.ROLE_CHANGE_REWARD,
                CoinRecordType.ONE_TIME,
                "首次修改角色补偿",
            )
            coin.role_change_reward = True
            coin.save(update_fields=["role_change_reward"])
        return super().save(**kwargs)

    class Meta:
        model = Role
        exclude = ("deleted",)
        read_only_fields = (
            "verify",
            "badges",
            "is_active",
            "banned_until",
            "editable",
            "following_count",
            "follower_count",
        )


class NotificationSerializer(serializers.ModelSerializer):
    class Meta:
        model = Notification
        fields = "__all__"
