"""Oracle: legacy extraction must fail instead of invoking Wine."""
import unittest
from unittest.mock import patch
from core.recipes.dotnet import DotNetRecipe
from core.recipes.electron import ElectronRecipe

class NoWineTests(unittest.TestCase):
    def test_electron_does_not_fall_back_to_wine(self):
        with patch('core.recipes.electron.shutil.which', side_effect=lambda name: '/wine' if name == 'wine' else None), \
             patch('core.recipes.electron.os.path.isfile', return_value=False), \
             patch('core.recipes.electron.subprocess.run') as run:
            self.assertFalse(ElectronRecipe()._extract_payload('/input.exe', '/output'))
            run.assert_not_called()

    def test_dotnet_does_not_fall_back_to_wine(self):
        with patch('core.recipes.dotnet.shutil.which', side_effect=lambda name: '/wine' if name == 'wine' else None), \
             patch('core.recipes.dotnet.os.path.isfile', return_value=False), \
             patch('core.recipes.dotnet.subprocess.run') as run:
            self.assertFalse(DotNetRecipe()._extract_payload('/input.exe', '/output', 'inno'))
            run.assert_not_called()

if __name__ == '__main__':
    unittest.main()
