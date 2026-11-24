from django.core.cache import cache
from django.test import TestCase
from rest_framework.test import APIClient

from gt_auth.test_support import add_key, authenticate, make_user
from .models import Alumni


class AlumniSecurityTests(TestCase):
    def setUp(self):
        cache.clear()
        self.client = APIClient()
        self.owner, self.owner_role = make_user("alumni_owner")
        self.other, self.other_role = make_user("alumni_other")
        self.entry = Alumni.objects.create(
            name=self.owner.real_name,
            year=2024,
            phone="13800138000",
            email="secret@st.shou.edu.cn",
            contact="wechat_secret",
            user=self.owner,
        )

    def test_list_omits_contact_pii_and_detail_requires_auth(self):
        anon_list = self.client.get("/alumni/")
        self.assertEqual(anon_list.status_code, 200)
        row = anon_list.data["results"][0]
        for field in ("phone", "email", "contact"):
            self.assertNotIn(field, row)
        self.assertEqual(self.client.get(f"/alumni/{self.entry.pk}/").status_code, 401)

    def test_horizontal_idor_and_empty_real_name_and_avatar_validation(self):
        authenticate(self.client, self.other, self.other_role)
        detail = self.client.get(f"/alumni/{self.entry.pk}/")
        self.assertEqual(detail.status_code, 200)
        self.assertFalse(detail.data["has_permission"])

        # Cannot create entry for someone else's name or with empty real_name
        self.assertEqual(self.client.post("/alumni/", {"name": self.owner.real_name, "year": 2024}, format="json").status_code, 403)
        self.other.real_name = ""
        self.other.save(update_fields=["real_name"])
        self.assertEqual(self.client.post("/alumni/", {"name": "", "year": 2024}, format="json").status_code, 400)
        self.other.real_name = "测试用户alumni_other"
        self.other.save(update_fields=["real_name"])
        self.assertEqual(
            self.client.post("/alumni/", {"name": self.other.real_name, "year": 2024, "avatar": "ftp://evil.example/a.png"}, format="json").status_code,
            400,
        )

        # Cannot update or delete another user's entry
        self.assertEqual(self.client.patch(f"/alumni/{self.entry.pk}/", {"phone": "110"}, format="json").status_code, 403)
        self.assertEqual(self.client.delete(f"/alumni/{self.entry.pk}/").status_code, 403)

    def test_global_reader_has_no_alumni_write_permission(self):
        gr, gr_role = make_user("alumni_gr", roles=["global_reader"])
        key, _ = add_key(gr)
        add_key(gr)
        authenticate(self.client, gr, gr_role, key=key)
        detail = self.client.get(f"/alumni/{self.entry.pk}/")
        self.assertEqual(detail.status_code, 200)
        self.assertFalse(detail.data["has_permission"])
        self.assertEqual(self.client.post("/alumni/", {"name": gr.real_name, "year": 2024}, format="json").status_code, 403)

        self.client.force_authenticate(user=gr)
        self.assertEqual(self.client.patch(f"/alumni/{self.entry.pk}/", {"phone": "110"}, format="json").status_code, 403)
        self.assertEqual(self.client.delete(f"/alumni/{self.entry.pk}/").status_code, 403)
