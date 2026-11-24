from rest_framework.mixins import CreateModelMixin, UpdateModelMixin, DestroyModelMixin
from rest_framework.permissions import IsAuthenticated
from rest_framework.exceptions import PermissionDenied
from rest_framework.viewsets import ReadOnlyModelViewSet
from django_filters import rest_framework as filters
from rest_framework.filters import OrderingFilter, SearchFilter

from .models import Alumni
from .serializers import AlumniListSerializer, AlumniSerializer
from gt_auth.models import User
from gt_auth.roles import assigned_roles


def _reject_global_reader(user):
    if user and user.is_authenticated and "global_reader" in assigned_roles(user.permission):
        raise PermissionDenied("全局读者仅可读取数据")


class AlumniViewset(ReadOnlyModelViewSet, CreateModelMixin, UpdateModelMixin, DestroyModelMixin):
    queryset = Alumni.objects.all().order_by("id")
    filter_backends = [filters.DjangoFilterBackend, OrderingFilter, SearchFilter]
    search_fields = ["name", "year", "academic_background", "work_experience"]
    ordering_fields = ["id", "name", "year"]

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
        _reject_global_reader(user)
        if not User.has_permission(user, "admin_alumni") and (
            not user.real_name or serializer.validated_data["name"] != user.real_name
        ):
            raise PermissionDenied("你没有为他人创建词条的权限！")
        serializer.save(user=user)

    def perform_update(self, serializer: AlumniSerializer):
        user = self.request.user
        _reject_global_reader(user)
        if not User.has_permission(user, "admin_alumni"):
            if serializer.instance.user != user:
                raise PermissionDenied("不能修改其他人的校友信息")
            serializer.save(name=serializer.instance.name)
        else:
            return super().perform_update(serializer)

    def perform_destroy(self, instance):
        user = self.request.user
        _reject_global_reader(user)
        if instance.user != user and not User.has_permission(user, "admin_alumni"):
            raise PermissionDenied("你没有删除他人校友信息的权限！")
        super().perform_destroy(instance)
