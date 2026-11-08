"""Unit and integration tests for Fallout New Vegas pipeline orchestrator."""

from pathlib import Path
import pytest

from core.transpiler.fallout_pipeline import detect_fallout_nv, FalloutPipeline


FALLOUT_DIR = Path("/home/danny/.local/share/Steam/steamapps/common/Fallout New Vegas")


def test_detect_nonexistent_path(tmp_path: Path):
    install = detect_fallout_nv(tmp_path / "nonexistent")
    assert install is None


@pytest.mark.skipif(not (FALLOUT_DIR / "Data/FalloutNV.esm").exists(), reason="Fallout NV not installed")
def test_detect_real_install():
    install = detect_fallout_nv(FALLOUT_DIR)
    assert install is not None
    assert install.esm_file.name == "FalloutNV.esm"
    assert "Fallout - Meshes.bsa" in install.bsa_files
    assert len(install.shader_files) == 16


@pytest.mark.skipif(not (FALLOUT_DIR / "Data/FalloutNV.esm").exists(), reason="Fallout NV not installed")
def test_pipeline_openmw_config(tmp_path: Path):
    install = detect_fallout_nv(FALLOUT_DIR)
    assert install is not None
    pipe = FalloutPipeline(install)

    cfg_path = tmp_path / "openmw.cfg"
    content = pipe.generate_openmw_config(cfg_path)

    assert cfg_path.exists()
    assert "data=" in content
    assert "fallback-archive=Fallout - Meshes.bsa" in content
    assert "fallback-archive=Fallout - Textures.bsa" in content
    assert "content=FalloutNV.esm" in content
