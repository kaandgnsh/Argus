#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# KaanDGN ARGUS

"""Graph export + ASCII world map.

Harita: Matthew Thomas, 1998.
Lisans: "Freely usable as long as this line is included."

NOT: Harita asagida '@' karakterleriyle kodlanmis olarak durur. Gercek
     bosluklar chat/markdown/editor tasimasinda kayboldugu icin '@' ile
     korunur. Modul import edildiginde _WORLD_MAP_DECODED olarak cozulur.
"""

from core.colors import Kırmızı, Yeşil, Sarı, Beyaz, Mor, Cyan, Bitir
from core import database as db
from core.reports import export_dot


# '@' = bosluk. Load sirasinda cozulur.
_WORLD_MAP_ENCODED = r"""
@@@180@@@150W@@120W@@90W@@@60W@@@30W@@@000@@@30E@@@60E@@@90E@@@120E@@150E@@180
@@@@|@@@@@|@@@@@|@@@@@|@@@@@|@@@@@|@@@@@|@@@@@|@@@@@|@@@@@|@@@@@|@@@@@|@@@@@|
90N-+-----+-----+-----+-----+-----+-----+-----+-----+-----+-----+-----+-----+-90N
@@@@|@@@@@@@@@@@.@_..::__:@@,-"-"._@@@@@@@@|7@@@@@@@,@@@@@_,.__@@@@@@@@@@@@@|
@@@@|@@@_.___@_@_<_>`!(._`.`-.@@@@/@@@@@@@@@_._@@@@@`_@,_/@@'@@'-._.---.-.__|
@@@@|>.{@@@@@"@"@`-==,',._\{@@\@@/@{)@@@@@@/@_@">_,-'@`@@@@@@@@@@@@@@@@mt-2_|
60N-+@@\_.:--.@@@@@@@`._@)`^-.@"'@@@@@@@,@[_/(@@@@@@@@@@@@@@@@@@@@@@@__,/-'@+-60N
@@@@|@'"'@@@@@\@@@@@@@@@"@@@@_L@@@@@@@@oD_,--'@@@@@@@@@@@@@@@@)@@@@@/.@(|@@@|
@@@@|@@@@@@@@@@|@@@@@@@@@@@,'@@@@@@@@@@_)_.\\._<>@6@@@@@@@@@@@@@@_,'@/@@'@@@|
@@@@|@@@@@@@@@@`.@@@@@@@@@/@@@@@@@@@@@[_/_'`@`"(@@@@@@@@@@@@@@@@<'}@@)@@@@@@|
30N-+@@@@@@@@@@@\\@@@@.-.@)@@@@@@@@@@@/@@@`-'"..'@`:._@@@@@@@@@@_)@@'@@@@@@@+-30N
@@@@|@@@@`@@@@@@@@\@@(@@`(@@@@@@@@@@@/@@@@@@@@@`:\@@>\@,,-^.@@/'@'@@@@@@@@@|
@@@@|@@@@@@@@@@@@@@`._,@@@""@@@@@@@@@|@@@@@@@@@@@\`'@@@\|@@@?_)@@{\@@@@@@@@@|
@@@@|@@@@@@@@@@@@@@@@@`=.---.@@@@@@@@`._._@@@@@@@,'@@@@@"`@@|'@,-@'.@@@@@@@@|
000-+@@@@@@@@@@@@@@@@@@@|@@@@`-._@@@@@@@@@|@@@@@/@@@@@@@@@@`:`<_|h--._@@@@@@+-000
@@@@|@@@@@@@@@@@@@@@@@@@(@@@@@@@@>@@@@@@@@.@@@@@|@,@@@@@@@@@@`=.__.`-'\@@@@@|
@@@@|@@@@@@@@@@@@@@@@@@@@`.@@@@@/@@@@@@@@@|@@@@@|{|@@@@@@@@@@@@@@,-.,\@@@@@.|
@@@@|@@@@@@@@@@@@@@@@@@@@@|@@@,'@@@@@@@@@@@\@@@/@`'@@@@@@@@@@@@,"@@@@@\@@@@@|
30S-+@@@@@@@@@@@@@@@@@@@@@|@@/@@@@@@@@@@@@@@|_'@@@@@@@@@@@@@@@@|@@__@@/@@@@@+-30S
@@@@|@@@@@@@@@@@@@@@@@@@@@|@|@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@'-'@@`-'@@@\.|
@@@@|@@@@@@@@@@@@@@@@@@@@@|/@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@"@@@@/@|
@@@@|@@@@@@@@@@@@@@@@@@@@@\.@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@'@@|
60S-+@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@+-60S
@@@@|@@@@@@@@@@@@@@@@@@@@@@,/@@@@@@@@@@@@______._.--._@_..---.---------._@@@|
@@@@|@@@@@,-----"-..?----_/@)@@@@@@__,-'"@@@@@@@@@@@@@"@@@@@@@@@@@@@@@@@@(@@|
@@@@|-.._(@@@@@@@@@@@@@@@@@@`-----'@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@`-|
90S-+-----+-----+-----+-----+-----+-----+-----+-----+-----+-----+-----+-----+-90S
@@@@Map@1998@Matthew@Thomas.|Freely@usable@as@long@as@this|line@is@included.|
@@@@|@@@@@|@@@@@|@@@@@|@@@@@|@@@@@|@@@@@|@@@@@|@@@@@|@@@@@|@@@@@|@@@@@|@@@@@|
@@@180@@@150W@@120W@@90W@@@60W@@@30W@@@000@@@30E@@@60E@@@90E@@@120E@@150E@@180
"""

# Cozum: '@' -> bosluk, bastaki/sondaki bos satirlari at
_WORLD_MAP_DECODED = _WORLD_MAP_ENCODED.replace("@", " ").strip("\n").split("\n")

# Matthew Thomas haritasinin gercek cizim sinirlari
LAT_TOP = 78.0
LAT_BOTTOM = -78.0
LON_LEFT = -180.0
LON_RIGHT = 180.0


def _latlon_to_xy(lat, lon, width, height):
    if lat is None or lon is None:
        return None, None
    try:
        lat_f = float(lat)
        lon_f = float(lon)
    except (TypeError, ValueError):
        return None, None
    if not (LAT_BOTTOM <= lat_f <= LAT_TOP):
        return None, None
    if not (LON_LEFT <= lon_f <= LON_RIGHT):
        return None, None

    nx = (lon_f - LON_LEFT) / (LON_RIGHT - LON_LEFT)
    ny = (LAT_TOP - lat_f) / (LAT_TOP - LAT_BOTTOM)
    x = int(nx * (width - 1))
    y = int(ny * (height - 1))
    return max(0, min(width - 1, x)), max(0, min(height - 1, y))


def ascii_map(lat, lon, marker="★"):
    lines = _WORLD_MAP_DECODED
    if not lines:
        return None

    width = max(len(line) for line in lines)
    height = len(lines)

    x, y = _latlon_to_xy(lat, lon, width, height)
    if x is None:
        return None

    grid = [list(line.ljust(width)) for line in lines]
    grid[y][x] = marker

    output = []
    for row_chars in grid:
        row_str = "".join(row_chars)
        if marker in row_str:
            idx = row_str.index(marker)
            before = row_str[:idx]
            after = row_str[idx + 1:]
            colored = f"{Cyan}{before}{Bitir}{Sarı}{marker}{Bitir}{Cyan}{after}{Bitir}"
        else:
            colored = f"{Cyan}{row_str}{Bitir}"
        output.append(colored)
    return "\n".join(output)


def show_map(ip, lat, lon):
    print(f"\n{Sarı}[*]{Bitir} Dünya haritası...")
    m = ascii_map(lat, lon)
    if m:
        print(m)
        print(f"\n  {Beyaz}Koordinat:{Bitir} {Yeşil}{lat}, {lon}{Bitir}")
        print(f"  {Sarı}⚠  IP tabanlı konum şehir düzeyinde tahmindir.{Bitir}")
    else:
        print(f"  {Mor}[i]{Bitir} Koordinat aralık dışında.")
        if lat is not None and lon is not None:
            print(f"  {Mor}[i]{Bitir} Koordinat: {Yeşil}{lat}, {lon}{Bitir}")


def export_graph():
    print(f"\n{Sarı}[*]{Bitir} GraphViz DOT export...")
    try:
        path = export_dot()
        print(f"  {Yeşil}[✓]{Bitir} {path}")
        print(f"  {Mor}Görsele çevirmek için:{Bitir}")
        print(f"    {Cyan}dot -Tpng {path} -o graph.png{Bitir}")
    except Exception as e:
        print(f"  {Mor}[!]{Bitir} DOT export: {e}")