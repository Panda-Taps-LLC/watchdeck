import os
import requests
# subprocess.run(["ls"])  # comment: must not fire
token = os.environ.get("FAKE_API_TOKEN")
r = requests.get("https://example.invalid", headers={"x": token})
