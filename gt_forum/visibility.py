from django.db.models import Q
from gt_auth.models import IdentityChoice, SchoolChoice, Role
from gt_admin._models import ReviewStatusChoice
from .models import Post, PostComment, PostShareWithChoice


def visible_posts(user, current_role=None):
    public = Q(share_with=PostShareWithChoice.PUBLIC)
    own = Q(pk__in=[])
    if user and user.is_authenticated:
        memberships = Role.objects.filter(members__user=user, deleted=False, is_active=True).values("id")
        own |= Q(share_with=PostShareWithChoice.PRIVATE, author_id__in=memberships)
        if current_role is not None:
            own |= Q(author=current_role)
        if user.email_verified_at and user.school == SchoolChoice.SHOU:
            public |= Q(share_with=PostShareWithChoice.SCHOOL)
            if user.identity == IdentityChoice.STUDENT:
                public |= Q(share_with=PostShareWithChoice.STUDENT)
    return Post.objects.filter(deleted=False).filter(
        (public & Q(review_status__gte=ReviewStatusChoice.NO_NEED)) | own
    ).distinct()


def visible_comments(user, current_role=None):
    visible = Q(review_status__gte=ReviewStatusChoice.NO_NEED)
    if current_role:
        visible |= Q(author=current_role)
    return PostComment.objects.filter(
        post__in=visible_posts(user, current_role), post__allow_comment=True, hidden=False,
    ).filter(visible).distinct()
