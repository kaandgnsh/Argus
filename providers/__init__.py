#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# KaanDGN ARGUS

"""Provider package.

Bu dosya, `providers/` klasöründeki tüm provider modüllerini import ederek
@register dekoratörünün çalışmasını ve registry'nin dolmasını sağlar.
Aksi halde registry boş kalır ve tüm provider'lar sessizce devre dışı kalır.

Yeni provider eklerken bu dosyaya dokunmana gerek yok — otomatik keşif yapılır.
"""

import importlib
import os
import pkgutil


_SKIP = {"base", "registry", "__init__"}


def _autoload():
    """providers/ klasöründeki tüm modülleri import eder."""
    pkg_dir = os.path.dirname(__file__)
    for _finder, name, _ispkg in pkgutil.iter_modules([pkg_dir]):
        if name in _SKIP or name.startswith("_"):
            continue
        try:
            importlib.import_module(f"providers.{name}")
        except Exception:
            # Tek bir provider import edilemezse diğerleri çalışmaya devam eder
            pass


_autoload()