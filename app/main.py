from app.core.config import load_config


def main() -> None:
    config = load_config()

    print("RDRS - Ransomware Detection and Response System")
    print("Status: initialized")
    print(f"Monitoring: {config['monitoring']['watch_paths']}")


if __name__ == "__main__":
    main()