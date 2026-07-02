import logging
import os
import sys


def pytest_configure(config):
    logging.basicConfig(
        level=logging.DEBUG,
        format='%(asctime)s %(levelname)s %(name)s: %(message)s'
    )

    print("\n=== DEBUG SESSION INFO ===")
    print(f"Python: {sys.version}")
    print(f"TPP_URL:   {os.environ.get('TPP_URL', 'NOT SET')}")
    print(f"TPP_ZONE:  {os.environ.get('TPP_ZONE', 'NOT SET')}")
    print(f"CLOUD_URL: {os.environ.get('CLOUD_URL', 'NOT SET')}")

    for pkg in ('requests', 'urllib3', 'cryptography', 'pynacl', 'vcert'):
        try:
            import importlib.metadata
            version = importlib.metadata.version(pkg)
        except Exception:
            version = 'unknown'
        print(f"  {pkg}: {version}")

    print("=========================\n")
