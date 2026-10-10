
import time
from pathlib import Path
import secrets

SANDBOX = Path("data/sandbox/e2e_test")
SANDBOX.mkdir(parents=True, exist_ok=True)

PREFIX = "e2e_simulation_"


def random_data(size=4096):
    return secrets.token_bytes(size)


def create_test_files():
    print("[1] Creating harmless test files...")

    files = []

    for index in range(12):
        path = SANDBOX / f"{PREFIX}{index}.txt"
        path.write_bytes(random_data())
        files.append(path)

    time.sleep(3)
    return files


def simulate_rapid_modifications(path):
    print("[2] Simulating rapid file modifications...")

    for index in range(22):
        path.write_bytes(random_data())
        print(f"Modification {index + 1}/22")
        time.sleep(1.1)


def simulate_mass_renaming(files):
    print("[3] Simulating mass file renaming...")

    for index, path in enumerate(files[:10]):
        renamed = path.with_suffix(".locked")
        path.rename(renamed)
        print(f"Rename {index + 1}/10")
        time.sleep(1.1)


def main():
    files = create_test_files()

    simulate_rapid_modifications(files[0])
    simulate_mass_renaming(files)

    print("\nSimulation completed.")
    print("All generated files remain in the sandbox.")
    print("No original files were deleted or encrypted.")


if __name__ == "__main__":
    main()
