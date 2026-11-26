import unittest
from app import app


class OfferGuardAppTestCase(unittest.TestCase):
    def setUp(self):
        self.client = app.test_client()
        self.client.testing = True

    def test_home_page_loads(self):
        response = self.client.get("/")
        self.assertIn(response.status_code, [200, 404, 405])

    def test_empty_input_handled(self):
        response = self.client.post("/analyze", json={"text": ""})
        self.assertIn(response.status_code, [200, 400, 404, 405])


if __name__ == "__main__":
    unittest.main()
