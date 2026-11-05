"""Account directory and invitation consent are separate permissions."""
from django.db.models import Q
from .models import User


def discoverable_users(actor):
    users = User.objects.filter(is_active=True)
    if User.has_permission(actor, "admin_user"):
        return users
    if not actor or not actor.is_authenticated:
        return users.none()
    return users.filter(Q(pk=actor.pk) | Q(privacy__allow_show_in_list=True) |
                        Q(trusted_users__trusted_user=actor)).distinct()


def invitable_users(actor):
    if not actor or not actor.is_authenticated:
        return User.objects.none()
    return User.objects.filter(is_active=True).filter(
        Q(privacy__accept_join_role=True) | Q(trusted_users__trusted_user=actor)
    ).distinct()
