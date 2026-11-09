"""Tests locaux sans réseau pour les fonctions ajoutées au MVP NeuroBouclier."""
import importlib.util
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
TEMP = tempfile.TemporaryDirectory()
os.environ["CW_DB"] = str(Path(TEMP.name) / "neurobouclier-tests.db")
spec = importlib.util.spec_from_file_location("cyberwatch_test_module", ROOT / "cyberwatch.py")
cw = importlib.util.module_from_spec(spec)
spec.loader.exec_module(cw)


class NeuroBouclierFeatureTests(unittest.TestCase):
    def setUp(self):
        cw.DB_PATH = Path(TEMP.name) / "neurobouclier-tests.db"
        if cw.DB_PATH.exists():
            cw.DB_PATH.unlink()
        cw.init_db()

    def test_new_event_creates_open_incident(self):
        cw.record_event("Élevé", "Test", "Événement de test", "Événement local de test")
        rows = cw.incidents_data()
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["status"], "open")
        self.assertEqual(rows[0]["title"], "Événement de test")

    def test_incident_can_be_assigned_and_resolved(self):
        cw.record_event("Moyen", "Test", "Incident", "Détail")
        incident = cw.incidents_data()[0]
        result = cw.update_incident({
            "incident_id": incident["id"],
            "status": "resolved",
            "assignee": "Analyste pilote",
            "resolution": "Vérification terminée; aucune action automatique.",
        })
        self.assertEqual(result["status"], "resolved")
        updated = cw.incidents_data()[0]
        self.assertEqual(updated["assignee"], "Analyste pilote")
        self.assertEqual(updated["resolution"], "Vérification terminée; aucune action automatique.")

    def test_invalid_incident_status_is_rejected(self):
        cw.record_event("Faible", "Test", "Incident", "Détail")
        incident = cw.incidents_data()[0]
        with self.assertRaises(ValueError):
            cw.update_incident({"incident_id": incident["id"], "status": "blocked"})

    def test_cisa_catalogue_import_is_validated_and_upserted(self):
        feed = {
            "vulnerabilities": [{
                "cveID": "CVE-2025-12345",
                "vendorProject": "Vendor",
                "product": "Product",
                "vulnerabilityName": "Test vulnerability",
                "dateAdded": "2025-01-02",
                "dueDate": "2025-01-20",
                "knownRansomwareCampaignUse": "Unknown",
                "shortDescription": "Description test",
                "requiredAction": "Installer le correctif officiel",
            }, {
                "cveID": "INVALID-CVE",
                "vendorProject": "Ignored",
                "product": "Ignored",
            }]
        }
        with patch.object(cw, "http_get", return_value=json.dumps(feed)):
            result = cw.refresh_vulnerabilities()
        self.assertEqual(result["count"], 1)
        rows = cw.vulnerabilities_data()
        self.assertEqual(rows[0]["cve"], "CVE-2025-12345")
        self.assertEqual(rows[0]["vendor"], "Vendor")


if __name__ == "__main__":
    unittest.main()
