from datetime import date
from django.core.cache import cache
from django.test import TestCase
from rest_framework.test import APIClient

from gt_auth.test_support import add_key, authenticate, make_user
from .models import Coin, CoinRecord, CoinRecordType


class CoinSecurityTests(TestCase):
    def setUp(self):
        cache.clear()
        self.client = APIClient()
        self.alice, self.alice_role = make_user("coin_alice")
        self.bob, self.bob_role = make_user("coin_bob")
        Coin.objects.filter(pk=self.alice.coin_id).update(total=50)
        Coin.objects.filter(pk=self.bob.coin_id).update(total=50)

    def test_coin_records_and_transfer_scoping_and_bounds(self):
        self.bob.coin.add_record(5, CoinRecordType.DAILY, "bob secret")
        authenticate(self.client, self.alice, self.alice_role)
        self.assertEqual(self.client.get("/coin/").data["data"], [])
        self.assertEqual(self.client.get(f"/coin/{date.today()}/").status_code, 404)
        self.assertEqual(self.client.get("/coin/detail/").data["total"], 50)

        # Hidden, banned, self, and overflowing transfer targets are rejected
        self.assertEqual(self.client.post("/coin/transfer/", {"to_user_id": self.bob.pk, "amount": 5}, format="json").status_code, 404)
        self.assertEqual(self.client.post("/coin/transfer/", {"to_user_id": self.alice.pk, "amount": 5}, format="json").status_code, 404)
        self.assertEqual(self.client.post("/coin/transfer/", {"to_user_id": 10**30, "amount": 5}, format="json").status_code, 400)
        self.assertEqual(self.client.post("/coin/transfer/", {"to_user_id": self.bob.pk, "amount": 10**9}, format="json").status_code, 400)

        self.bob.privacy.allow_show_in_list = True
        self.bob.privacy.save(update_fields=["allow_show_in_list"])
        self.bob.is_active = False
        self.bob.save(update_fields=["is_active"])
        self.assertEqual(self.client.post("/coin/transfer/", {"to_user_id": self.bob.pk, "amount": 5}, format="json").status_code, 404)

    def test_global_reader_cannot_sign_or_transfer(self):
        gr, gr_role = make_user("coin_gr", roles=["global_reader"])
        key, _ = add_key(gr)
        add_key(gr)
        self.bob.privacy.allow_show_in_list = True
        self.bob.privacy.save(update_fields=["allow_show_in_list"])
        Coin.objects.filter(pk=gr.coin_id).update(total=50)

        authenticate(self.client, gr, gr_role, key=key)
        self.assertEqual(self.client.post("/coin/sign/").status_code, 403)
        self.assertEqual(self.client.post("/coin/transfer/", {"to_user_id": self.bob.pk, "amount": 1}, format="json").status_code, 403)

        self.client.force_authenticate(user=gr)
        self.assertEqual(self.client.post("/coin/sign/").status_code, 403)
        self.assertEqual(self.client.post("/coin/transfer/", {"to_user_id": self.bob.pk, "amount": 1}, format="json").status_code, 403)

    def test_coin_overflow_and_admin_coin_bounds_prevent_inf_lockout(self):
        from rest_framework.exceptions import ValidationError as DRFValidationError
        admin_user, admin_role = make_user("coin_admin_user", roles=["admin_user"])
        k1, _ = add_key(admin_user)
        add_key(admin_user)
        admin_client = APIClient()
        authenticate(admin_client, admin_user, admin_role, key=k1)

        # Admin coin endpoint must reject huge float values before they can overflow to inf.
        res = admin_client.post(f"/admin/user/{self.alice.pk}/coin/", {"change": 1e308, "type": "admin"}, format="json")
        self.assertEqual(res.status_code, 400)

        # Model-level add_record and update_total also reject overflow beyond MAX_COIN_TOTAL / inf.
        Coin.objects.filter(pk=self.alice.coin_id).update(total=1e15)
        self.alice.coin.refresh_from_db()
        with self.assertRaises(DRFValidationError):
            self.alice.coin.add_record(10.0, CoinRecordType.ADMIN, "overflow")
        with self.assertRaises(DRFValidationError):
            self.alice.coin.update_total(1e15)

        # User login remains healthy and JSON-serializable.
        login = APIClient().post("/security/password-login/", {"username": self.alice.username, "password": "GuaTian!Secure-2026"}, format="json")
        self.assertEqual(login.status_code, 200)
