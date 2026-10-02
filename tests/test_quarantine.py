from app.core.quarantine import QuarantineManager


def test_quarantine_copies_file_without_modifying_original(tmp_path):
    source = tmp_path / "important.txt"
    source.write_text("Harmless test data")

    quarantine = tmp_path / "quarantine"

    manager = QuarantineManager(
        quarantine_path=str(quarantine),
        simulation_mode=True,
    )

    result = manager.quarantine_file(str(source))

    copied_file = quarantine / "important.txt"

    assert result == str(copied_file)
    assert copied_file.exists()
    assert copied_file.read_text() == "Harmless test data"
    assert source.exists()
    assert source.read_text() == "Harmless test data"


def test_quarantine_handles_duplicate_filenames(tmp_path):
    source_a = tmp_path / "source_a"
    source_b = tmp_path / "source_b"
    source_a.mkdir()
    source_b.mkdir()

    file_a = source_a / "sample.txt"
    file_b = source_b / "sample.txt"

    file_a.write_text("First file")
    file_b.write_text("Second file")

    quarantine = tmp_path / "quarantine"

    manager = QuarantineManager(
        quarantine_path=str(quarantine),
    )

    result_a = manager.quarantine_file(str(file_a))
    result_b = manager.quarantine_file(str(file_b))

    assert result_a != result_b
    assert (quarantine / "sample.txt").read_text() == "First file"
    assert (quarantine / "sample_1.txt").read_text() == "Second file"


def test_quarantine_ignores_missing_file(tmp_path):
    manager = QuarantineManager(
        quarantine_path=str(tmp_path / "quarantine"),
    )

    result = manager.quarantine_file(
        str(tmp_path / "missing.txt")
    )

    assert result is None
    assert not (tmp_path / "quarantine").exists()


def test_quarantine_ignores_directories(tmp_path):
    directory = tmp_path / "folder"
    directory.mkdir()

    manager = QuarantineManager(
        quarantine_path=str(tmp_path / "quarantine"),
    )

    result = manager.quarantine_file(str(directory))

    assert result is None
    assert directory.exists()
    assert not (tmp_path / "quarantine").exists()