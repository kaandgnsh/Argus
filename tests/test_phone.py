#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# KaanDGN ARGUS

from modules.phone import normalize


def test_tr_mobile_with_zero():
    assert normalize("05551234567") == "+905551234567"


def test_tr_mobile_no_prefix():
    assert normalize("5551234567") == "+905551234567"


def test_tr_with_country_code():
    assert normalize("905551234567") == "+905551234567"


def test_international():
    assert normalize("+14155552671") == "+14155552671"


def test_empty():
    assert normalize("") == ""
    assert normalize(None) == ""