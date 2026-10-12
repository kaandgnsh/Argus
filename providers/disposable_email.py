#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# KaanDGN ARGUS

"""Disposable email domain tespiti — offline liste + opsiyonel güncelleme."""

import os

from providers.base import Provider, ProviderUnavailable
from providers.registry import register


LIST_PATH = os.path.join("data", "disposable_domains.txt")
REMOTE_URL = (
    "https://raw.githubusercontent.com/disposable-email-domains/"
    "disposable-email-domains/master/disposable_email_blocklist.conf"
)


_BUILTIN = """
10minutemail.com
guerrillamail.com
guerrillamail.net
guerrillamail.org
sharklasers.com
grr.la
mailinator.com
mailinator.net
mailinator.org
trashmail.com
trashmail.io
trashmail.me
trashmail.net
trashmail.org
temp-mail.org
tempmail.com
tempmail.net
tempmail.org
tempmail.de
throwawaymail.com
yopmail.com
yopmail.fr
yopmail.net
fakeinbox.com
mailnesia.com
maildrop.cc
dispostable.com
throwam.com
tempr.email
discard.email
spambog.com
spamgourmet.com
spamgourmet.net
mytrashmail.com
trashymail.com
trashymail.net
wegwerfmail.de
meltmail.com
mailexpire.com
sogetthis.com
spamavert.com
spamfree24.org
spamfree24.de
spamfree24.net
spamspot.com
spam.la
spaml.com
supergreatmail.com
teleworm.com
teleworm.us
tempemail.com
tempemail.net
tempinbox.co.uk
tempinbox.com
temporaryemail.net
temporaryinbox.com
thisisnotmyrealemail.com
throwawayemailaddress.com
veryrealemail.com
webemail.me
whyspam.me
willselfdestruct.com
wuzup.net
xagloo.com
xemaps.com
xents.com
xoxy.net
yep.it
yogamaven.com
yuurok.com
zehnminuten.de
zehnminutenmail.de
zippymail.info
zoemail.org
temp-mail.io
tempmailo.com
tempmail.plus
tempail.com
fakemail.net
mail-temp.com
mohmal.com
getnada.com
emailondeck.com
inboxkitten.com
mailcatch.com
harakirimail.com
mailsac.com
"""


@register
class DisposableEmail(Provider):
    name = "disposable_email"
    enabled = True
    timeout = 15
    requires_key = False

    def _load_list(self):
        if os.path.exists(LIST_PATH):
            try:
                with open(LIST_PATH, "r", encoding="utf-8") as f:
                    return {l.strip().lower() for l in f if l.strip()
                            and not l.startswith("#")}
            except OSError:
                pass
        return {l.strip().lower() for l in _BUILTIN.splitlines() if l.strip()}

    def is_disposable(self, domain):
        return domain.strip().lower() in self._load_list()

    def update(self):
        r = self.get(REMOTE_URL)
        if r.status_code != 200:
            raise ProviderUnavailable(f"disposable_email: HTTP {r.status_code}")
        lines = [l.strip() for l in r.text.splitlines()
                 if l.strip() and not l.startswith("#")]
        os.makedirs(os.path.dirname(LIST_PATH) or ".", exist_ok=True)
        with open(LIST_PATH, "w", encoding="utf-8") as f:
            f.write("\n".join(lines))
        return len(lines)

    def query(self, email_or_domain):
        domain = email_or_domain.split("@")[-1].lower()
        return {"domain": domain, "disposable": self.is_disposable(domain)}