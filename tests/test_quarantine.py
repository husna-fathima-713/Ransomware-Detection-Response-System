
import pytest

from app.core.quarantine import QuarantineManager
import app.core.quarantine as quarantine_module


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

    manager = QuarantineManager(quarantine_path=str(quarantine))

    result_a = manager.quarantine_file(str(file_a))
    result_b = manager.quarantine_file(str(file_b))

    assert result_a != result_b
    assert (quarantine / "sample.txt").read_text() == "First file"
    assert (quarantine / "sample_1.txt").read_text() == "Second file"


def test_quarantine_ignores_missing_file(tmp_path):
    manager = QuarantineManager(
        quarantine_path=str(tmp_path / "quarantine"),
    )

    result = manager.quarantine_file(str(tmp_path / "missing.txt"))

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


def test_quarantine_handles_copy_failure(tmp_path, monkeypatch):
    source = tmp_path / "suspicious.txt"
    original_content = "Harmless test data"
    source.write_text(original_content)

    quarantine = tmp_path / "quarantine"

    def failed_copy(source_path, destination_path):
        with open(destination_path, "w") as file:
            file.write("Incomplete copy")
        raise OSError("Simulated copy failure")

    monkeypatch.setattr(
        quarantine_module.shutil,
        "copy2",
        failed_copy,
    )

    manager = QuarantineManager(quarantine_path=str(quarantine))

    result = manager.quarantine_file(str(source))

    assert result is None
    assert source.exists()
    assert source.read_text() == original_content
    assert not (quarantine / "suspicious.txt").exists()


def test_quarantine_continues_after_copy_failure(tmp_path, monkeypatch):
    source_dir = tmp_path / "sandbox"
    source_dir.mkdir()

    failed_file = source_dir / "failed.txt"
    successful_file = source_dir / "successful.txt"

    failed_file.write_text("First harmless file")
    successful_file.write_text("Second harmless file")

    quarantine = tmp_path / "quarantine"
    original_copy2 = quarantine_module.shutil.copy2

    def selective_copy_failure(source_path, destination_path):
        if source_path.name == "failed.txt":
            with open(destination_path, "w") as file:
                file.write("Incomplete copy")
            raise OSError("Simulated copy failure")

        return original_copy2(source_path, destination_path)

    monkeypatch.setattr(
        quarantine_module.shutil,
        "copy2",
        selective_copy_failure,
    )

    manager = QuarantineManager(quarantine_path=str(quarantine))

    results = manager.quarantine_files([
        str(failed_file),
        str(successful_file),
    ])

    assert len(results) == 1
    assert results[0] == str(quarantine / "successful.txt")
    assert (quarantine / "successful.txt").read_text() == (
        "Second harmless file"
    )
    assert not (quarantine / "failed.txt").exists()

    assert failed_file.read_text() == "First harmless file"
    assert successful_file.read_text() == "Second harmless file"


def test_quarantine_rejects_invalid_simulation_mode(tmp_path):
    with pytest.raises(TypeError):
        QuarantineManager(
            quarantine_path=str(tmp_path / "quarantine"),
            simulation_mode="true",
        )


def test_quarantine_rejects_empty_destination():
    with pytest.raises(ValueError):
        QuarantineManager(quarantine_path=" ")


def test_quarantine_rejects_invalid_destination_type():
    with pytest.raises(TypeError):
        QuarantineManager(quarantine_path=123)


def test_quarantine_rejects_invalid_file_path(tmp_path):
    manager = QuarantineManager(
        quarantine_path=str(tmp_path / "quarantine"),
    )

    with pytest.raises(TypeError):
        manager.quarantine_file(123)


def test_quarantine_files_rejects_non_list(tmp_path):
    manager = QuarantineManager(
        quarantine_path=str(tmp_path / "quarantine"),
    )

    with pytest.raises(TypeError):
        manager.quarantine_files("file.txt")


def test_quarantine_skips_source_already_in_quarantine(tmp_path):
    quarantine = tmp_path / "quarantine"
    quarantine.mkdir()

    source = quarantine / "already_quarantined.txt"
    source.write_text("Existing evidence")

    manager = QuarantineManager(quarantine_path=str(quarantine))

    result = manager.quarantine_file(str(source))

    assert result is None
    assert source.read_text() == "Existing evidence"


def test_quarantine_skips_symbolic_link(tmp_path):
    source = tmp_path / "original.txt"
    source.write_text("Original content")

    link = tmp_path / "linked.txt"

    try:
        link.symlink_to(source)
    except (OSError, NotImplementedError):
        pytest.skip("Symbolic links are not available on this system.")

    manager = QuarantineManager(
        quarantine_path=str(tmp_path / "quarantine"),
    )

    result = manager.quarantine_file(str(link))

    assert result is None
    assert source.read_text() == "Original content"
    assert not (tmp_path / "quarantine").exists()


def test_quarantine_preserves_original_when_simulation_disabled(tmp_path):
    source = tmp_path / "sample.txt"
    source.write_text("Preserve this file")

    manager = QuarantineManager(
        quarantine_path=str(tmp_path / "quarantine"),
        simulation_mode=False,
    )

    result = manager.quarantine_file(str(source))

    assert result is not None
    assert source.exists()
    assert source.read_text() == "Preserve this file"
    assert (tmp_path / "quarantine" / "sample.txt").read_text() == (
        "Preserve this file"
    )


def test_quarantine_reserves_existing_filename_safely(tmp_path):
    source = tmp_path / "sample.txt"
    source.write_text("New evidence")

    quarantine = tmp_path / "quarantine"
    quarantine.mkdir()

    existing = quarantine / "sample.txt"
    existing.write_text("Existing evidence")

    manager = QuarantineManager(quarantine_path=str(quarantine))

    result = manager.quarantine_file(str(source))

    assert result == str(quarantine / "sample_1.txt")
    assert existing.read_text() == "Existing evidence"
    assert (quarantine / "sample_1.txt").read_text() == "New evidence"
