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
