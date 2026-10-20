"""Tests for the central validation module."""

import pytest
from ldap3.utils.conv import escape_filter_chars

from active_directory_mcp import validation as v

BASE = "DC=corp,DC=example,DC=com"


# --- filter value escaping -------------------------------------------------


def test_escape_filter_value_matches_ldap3():
    raw = "a*(b)\\c\x00"
    assert v.escape_filter_value(raw) == escape_filter_chars(raw)


def test_escape_filter_value_no_wildcard_or_double_escape():
    out = v.escape_filter_value("a*b\\c")
    assert "*" not in out
    assert out == "a\\2ab\\5cc"


def test_escape_filter_value_non_str_coerced():
    assert v.escape_filter_value(5) == "5"


def test_eq_filter_escapes_injection():
    atom = v.eq_filter("sAMAccountName", "x)(objectClass=*")
    assert atom == "(sAMAccountName=x\\29\\28objectClass=\\2a)"


@pytest.mark.parametrize("name", ["", "1abc", "a b", "cn;binary", "a)(b", "a=b", None])
def test_eq_filter_rejects_bad_attribute(name):
    with pytest.raises(v.ValidationError):
        v.eq_filter(name, "x")


def test_validate_attribute_name_ok():
    assert v.validate_attribute_name("msDS-Foo") == "msDS-Foo"


# --- object class ----------------------------------------------------------


@pytest.mark.parametrize("oc", ["user", "inetOrgPerson", "msDS-GroupManagedServiceAccount"])
def test_object_class_ok(oc):
    assert v.validate_object_class(oc) == oc


@pytest.mark.parametrize("oc", ["user)(|(objectClass=*", "", "a b", None, 5])
def test_object_class_rejected(oc):
    with pytest.raises(v.ValidationError):
        v.validate_object_class(oc)


# --- DN confinement --------------------------------------------------------


def test_validate_dn_under_base():
    dn = "CN=Bob,OU=Staff,DC=corp,DC=example,DC=com"
    assert v.validate_dn(dn, BASE) == dn


def test_validate_dn_case_and_whitespace():
    assert v.validate_dn("cn=Bob , ou=Staff,  dc=CORP,dc=example, dc=com", BASE)


def test_validate_dn_equal_to_base():
    assert v.validate_dn(BASE, BASE) == BASE


@pytest.mark.parametrize(
    "dn",
    [
        "CN=Bob,DC=evil,DC=com",
        "DC=example,DC=com",
        "CN=x,XDC=corp,DC=example,DC=com",
        "CN=x,DC=corp,DC=example,DC=com,DC=evil",
        "CN=x,DC=notcorp,DC=example,DC=com",
        "",
        "garbage",
        "CN=,DC=corp,DC=example,DC=com",
        None,
    ],
)
def test_validate_dn_rejects(dn):
    with pytest.raises(v.ValidationError):
        v.validate_dn(dn, BASE)


def test_validate_dn_escaped_comma_single_rdn():
    dn = "CN=Smith\\, John,OU=Staff,DC=corp,DC=example,DC=com"
    assert v.validate_dn(dn, BASE) == dn
    # An escaped comma must not let a fake base suffix through.
    with pytest.raises(v.ValidationError):
        v.validate_dn("CN=Smith\\,DC=corp\\,DC=example\\,DC=com", BASE)


def test_validate_dn_shape_only_without_base():
    assert v.validate_dn("CN=a,DC=x") == "CN=a,DC=x"
    with pytest.raises(v.ValidationError):
        v.validate_dn("CN=,DC=x")
    with pytest.raises(v.ValidationError):
        v.validate_dn("noequals")


def test_is_dn_under():
    assert v.is_dn_under("OU=a," + BASE, BASE)
    assert not v.is_dn_under("OU=a,DC=other", BASE)
    assert not v.is_dn_under("junk", BASE)


def test_escape_rdn_value():
    assert v.escape_rdn_value("x,OU=Admins") == "x\\,OU\\=Admins"


def test_build_dn_escapes_and_confines():
    parent = "OU=Staff," + BASE
    dn = v.build_dn("CN", "x,OU=Admins", parent, BASE)
    assert dn == "CN=x\\,OU\\=Admins," + parent
    from ldap3.utils.dn import parse_dn

    parts = parse_dn(dn, strip=True)
    assert len(parts) == len(parse_dn(parent, strip=True)) + 1
    assert parts[0][1] == "x\\,OU\\=Admins"


def test_build_dn_rejects_outside_parent():
    with pytest.raises(v.ValidationError):
        v.build_dn("CN", "x", "OU=a,DC=evil,DC=com", BASE)


@pytest.mark.parametrize("name", ["", None, "a\x00b"])
def test_build_dn_rejects_bad_value(name):
    with pytest.raises(v.ValidationError):
        v.build_dn("CN", name, BASE, BASE)


def test_build_dn_rejects_bad_rdn_type():
    with pytest.raises(v.ValidationError):
        v.build_dn("CN,OU", "x", BASE, BASE)


# --- filter_criteria -------------------------------------------------------


@pytest.mark.parametrize("frag", ["(department=IT)", "(&(a=1)(b=2))", "(a=1)(b=2)", "(!(a=*))"])
def test_filter_criteria_ok(frag):
    assert v.validate_filter_criteria(frag) == frag


@pytest.mark.parametrize(
    "frag",
    [
        "",
        "   ",
        "department=IT",
        "(a=1",
        "(a=1))(|(objectClass=*)",
        "(a=1)\x00",
        "(a=" + "x" * 1025 + ")",
        "(a=1))(b=2",
        ")(a=1)(",
        None,
        5,
    ],
)
def test_filter_criteria_rejected(frag):
    with pytest.raises(v.ValidationError):
        v.validate_filter_criteria(frag)


def test_filter_criteria_length_boundary():
    frag = "(a=" + "x" * (v.MAX_FILTER_CRITERIA_LENGTH - 4) + ")"
    assert len(frag) == v.MAX_FILTER_CRITERIA_LENGTH
    assert v.validate_filter_criteria(frag) == frag


def test_combine_filters():
    assert v.combine_filters("(objectClass=user)", "(a=1)") == "(&(objectClass=user)(a=1))"
    assert v.combine_filters("(objectClass=user)", None) == "(objectClass=user)"
    assert v.combine_filters("(objectClass=user)", "") == "(objectClass=user)"


def test_combine_filters_validates():
    with pytest.raises(v.ValidationError):
        v.combine_filters("(objectClass=user)", "(a=1))(|(x=*)")


def test_module_has_no_internal_imports():
    import inspect

    src = inspect.getsource(v)
    code = "\n".join(
        line for line in src.splitlines() if line.lstrip().startswith(("import ", "from "))
    )
    assert "active_directory_mcp" not in code
    assert "endswith" not in src


# --- review fixes (CR-01, CR-02, WR-01, WR-02, WR-06b) -----------------------


@pytest.mark.parametrize(
    "dn",
    [
        "CN=a+DC=corp,DC=example,DC=com",
        "CN=x,OU=y+DC=corp,DC=example,DC=com",
    ],
)
def test_multivalued_rdn_cannot_escape_base(dn):
    with pytest.raises(v.ValidationError):
        v.validate_dn(dn, BASE)
    assert v.is_dn_under(dn, BASE) is False


def test_multivalued_rdn_beneath_base_is_accepted():
    assert v.is_dn_under("CN=a+SN=b,OU=y," + BASE, BASE)


def test_allow_base_false_rejects_base_but_accepts_descendant():
    assert v.validate_dn(BASE, BASE) == BASE
    with pytest.raises(v.ValidationError):
        v.validate_dn(BASE, BASE, allow_base=False)
    with pytest.raises(v.ValidationError):
        v.validate_dn(BASE.lower().replace(",", ", "), BASE, allow_base=False)
    assert v.validate_dn("OU=a," + BASE, BASE, allow_base=False)


@pytest.mark.parametrize("fn", [v.validate_object_class, v.validate_attribute_name])
def test_names_reject_trailing_newline(fn):
    with pytest.raises(v.ValidationError):
        fn("user\n")


def test_eq_filter_rejects_attribute_with_newline():
    with pytest.raises(v.ValidationError):
        v.eq_filter("cn\n", "x")


@pytest.mark.parametrize(
    "fragment",
    [
        "(userPassword=a*)",
        "(UnicodePwd=*)",
        "(unicodePwd;binary=x)",
        "(ms-Mcs-AdmPwd=*)",
        "(msDS-KeyCredentialLink=*)",
        "(ntSecurityDescriptor=*)",
        "(|(cn=a)(!(msLAPS-Password=*)))",
        "(2.5.4.35=a*)",
        "(memberOf:1.2.840.113556.1.4.1941:=CN=x,DC=a)",
        "(cn:dn:=x)",
    ],
)
def test_filter_criteria_rejects_sensitive_and_extensible(fragment):
    with pytest.raises(v.ValidationError):
        v.validate_filter_criteria(fragment)


def test_filter_criteria_ordinary_terms_still_pass():
    assert v.validate_filter_criteria("(department=IT)(|(a=1)(!(b=2)))")
    assert v.validate_filter_criteria("(pwdLastSet=0)")


def test_build_dn_trailing_space_is_escaped_and_parses():
    dn = v.build_dn("CN", "a ", BASE, BASE)
    assert dn == "CN=a\\20," + BASE
    assert v.is_dn_under(dn, BASE)
