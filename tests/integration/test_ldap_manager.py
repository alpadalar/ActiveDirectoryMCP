"""Gerçek LDAP ortamında LDAPManager entegrasyon testleri."""

from ldap3 import BASE, MODIFY_REPLACE, SUBTREE


def test_connects_and_binds(ldap_manager):
    """LDAPManager gerçek sunucuya bağlanmalı ve oturum açmalı."""
    connection = ldap_manager.connect()
    assert connection.bound is True


def test_add_modify_delete_cycle(ldap_manager, test_ou_dn):
    """Ekle, güncelle, sil senaryosu gerçek LDAP'a karşı çalışmalı."""
    entry_dn = f"CN=Temp Entry,{test_ou_dn}"
    attributes = {
        "objectClass": [
            "top",
            "person",
            "organizationalPerson",
            "inetOrgPerson",
            "extensibleObject",
        ],
        "cn": "Temp Entry",
        "sn": "Entry",
        "givenName": "Temp",
        "displayName": "Temp Entry",
        "sAMAccountName": "temp-entry",
        "userAccountControl": "512",
    }

    assert ldap_manager.add(entry_dn, attributes) is True

    search_results = ldap_manager.search(
        search_base=test_ou_dn,
        search_filter="(cn=Temp Entry)",
        attributes=["cn"],
        search_scope=SUBTREE,
    )
    assert any(entry["dn"].lower() == entry_dn.lower() for entry in search_results)

    changes = {"description": [(MODIFY_REPLACE, ["Updated by tests"])]}
    assert ldap_manager.modify(entry_dn, changes) is True

    verify = ldap_manager.search(
        search_base=entry_dn,
        search_filter="(objectClass=*)",
        attributes=["description"],
        search_scope=BASE,
    )
    assert verify and verify[0]["attributes"].get("description", [""])[0] == "Updated by tests"

    assert ldap_manager.delete(entry_dn) is True

    remaining = ldap_manager.search(
        search_base=entry_dn,
        search_filter="(objectClass=*)",
        attributes=["cn"],
        search_scope=BASE,
    )
    assert remaining == []
