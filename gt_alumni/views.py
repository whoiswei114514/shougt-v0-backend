from rest_framework.mixins import CreateModelMixin, UpdateModelMixin, DestroyModelMixin
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.exceptions import ValidationError
from rest_framework.viewsets import ReadOnlyModelViewSet
from django_filters import rest_framework as filters
from rest_framework.filters import SearchFilter

from .models import Alumni
from .serializers import AlumniListSerializer, AlumniSerializer
from gt_auth.models import User


class AlumniViewset(ReadOnlyModelViewSet, CreateModelMixin, UpdateModelMixin, DestroyModelMixin):
    queryset = Alumni.objects.all().order_by("id")
    filter_backends = [filters.DjangoFilterBackend, SearchFilter]
    search_fields = ["name", "year", "academic_background", "work_experience"]

    def get_permissions(self):
        if self.action == "list":
            return []
        return [IsAuthenticated()]

    def get_serializer_class(self):
        if self.action == "list":
            return AlumniListSerializer
        return AlumniSerializer

    def perform_create(self, serializer):
        user = self.request.user
        if serializer.validated_data["name"] != user.real_name and not User.has_permission(user, "admin_alumni"):
            raise ValidationError("你没有为他人创建词条的权限！")
        serializer.save(user=user)

    def perform_update(self, serializer: AlumniSerializer):
        user = self.request.user
        if not User.has_permission(user, "admin_alumni"):
            if serializer.instance.user != user:
                raise ValidationError("不能修改其他人的校友信息")
            serializer.save(name=serializer.instance.name)
        else:
            return super().perform_update(serializer)

    def perform_destroy(self, instance):
        user = self.request.user
        if instance.user != user and not User.has_permission(user, "admin_alumni"):
            raise ValidationError("你没有删除他人校友信息的权限！")
        super().perform_destroy(instance)
