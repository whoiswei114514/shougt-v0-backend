import json
import os
import tempfile
from pathlib import Path
from unittest.mock import patch

from django.test import SimpleTestCase

from gt.settings import load_fido_attestation_trust


class FidoTrustLoaderTests(SimpleTestCase):
    def test_loads_external_json_and_yaml_and_deduplicates_by_id(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            trust_repo = root / "fips-fido-trust"
            certs_dir = trust_repo / "certs"
            data_dir = trust_repo / "data"
            certs_dir.mkdir(parents=True)
            data_dir.mkdir(parents=True)
            pem = certs_dir / "vendor.pem"
            pem.write_text("-----BEGIN CERTIFICATE-----\nTEST\n-----END CERTIFICATE-----\n", encoding="utf-8")

            json_file = data_dir / "trust.json"
            json_file.write_text(
                json.dumps(
                    [
                        {
                            "id": "ext-model-1",
                            "root_pem": "certs/vendor.pem",
                            "aaguids": ["11111111-1111-4111-8111-111111111111"],
                            "attachment": "cross-platform",
                            "assurance": "fips140-3-level2",
                        },
                        {
                            "id": "inline-item",
                            "root_pem": "certs/vendor.pem",
                            "aaguids": ["22222222-2222-4222-8222-222222222222"],
                            "attachment": "cross-platform",
                            "assurance": "fips140-2-level2",
                        },
                    ]
                ),
                encoding="utf-8",
            )
            yaml_file = data_dir / "extra.yaml"
            yaml_file.write_text(
                "- id: ext-model-yaml\n"
                "  root_pem: certs/vendor.pem\n"
                "  aaguids:\n"
                "  - 33333333-3333-4333-8333-333333333333\n"
                "  attachment: cross-platform\n"
                "  assurance: fips140-2-level3\n",
                encoding="utf-8",
            )

            local_pem = root / "backend" / "certs" / "local.pem"
            local_pem.parent.mkdir(parents=True)
            local_pem.write_text("LOCAL", encoding="utf-8")

            config = {
                "fido_attestation_trust": [
                    {
                        "id": "inline-item",
                        "root_pem": "certs/local.pem",
                        "aaguids": ["00000000-0000-4000-8000-000000000001"],
                        "attachment": "cross-platform",
                        "assurance": "fips140-2-level2",
                    }
                ],
                "fido_attestation_trust_files": [
                    str(json_file),
                    str(root / "missing-optional.json"),
                ],
            }
            with patch.dict(os.environ, {"SHOUGT_FIDO_TRUST_FILES": str(yaml_file)}):
                loaded = load_fido_attestation_trust(config, root / "backend")

        by_id = {entry["id"]: entry for entry in loaded}
        self.assertEqual(len(loaded), 3)
        self.assertEqual(Path(by_id["inline-item"]["root_pem"]), local_pem.resolve())
        self.assertEqual(Path(by_id["ext-model-1"]["root_pem"]), pem.resolve())
        self.assertEqual(Path(by_id["ext-model-yaml"]["root_pem"]), pem.resolve())
