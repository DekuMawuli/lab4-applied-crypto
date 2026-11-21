import dataclasses
from pathlib import Path

import pytest

from crypto_client.ca_info import load_ca_info
from crypto_client.cert import CertificateError, _check_fields, verify_certificate

TEST_CERT = (
    "prime number basis = 4294967291\r\n"
    "primitive element = 1000005\r\n"
    "username = mperkin2\r\n"
    "user public key = 1034503561\r\n"
    "----------------------------------------\r\n"
    "aubjeDsCo/9gC7KQR0Ifdmp82A5wVjlVJH+liYp6CvOwAVu0dVMM4keg5MTfoFsAIP4txpLTV3r2BBvh5R6Eu1w7"
    "j3hdfICZqJN60yFOyx5IWAlCksUBjEC1p0HplwaJeqPTFij22rk1+u1TfaEVCDe53IquC9uPGrkHb2feVcuc27cfc"
    "ZtspGxK5r7/4TIEecgsGTvjYhkjiQBBRujUYRBeWomVrXja/cacau8tE7z5dVgGb7Qn4VodwAQsSRjm5xdNpdBDgs"
    "X39V8c88Ea7ZUCQB0R5CHeaTuOSnZab6eyzxu2DUgXF0SCNOg4AjnZrSztPc4xDxH7K0vB8NYmjQ==\r\n"
).encode("ascii")


@pytest.fixture
def ca_info_fixture():
    return load_ca_info(Path(__file__).parent.parent.parent / "Pre_installed_CA_information.txt")


def test_valid_certificate_verifies(ca_info_fixture):
    c = verify_certificate(TEST_CERT, "mperkin2", ca_info_fixture)
    assert c.username == "mperkin2"
    assert c.public_key == 1034503561


def test_tampered_byte_in_body_fails(ca_info_fixture):
    tampered = TEST_CERT.replace(b"mperkin2", b"mperkin3", 1)
    with pytest.raises(CertificateError):
        verify_certificate(tampered, "mperkin3", ca_info_fixture)


def test_wrong_requested_username_rejected(ca_info_fixture):
    with pytest.raises(CertificateError):
        verify_certificate(TEST_CERT, "someoneelse", ca_info_fixture)


def test_p_alpha_mismatch_rejected(ca_info_fixture):
    # p must stay well above the certificate's public key (1034503561), otherwise
    # the range check would reject it first and this would no longer test the
    # p/alpha comparison at all.
    bad_info = dataclasses.replace(ca_info_fixture, p=4294967290)
    with pytest.raises(CertificateError, match="p/alpha"):
        verify_certificate(TEST_CERT, "mperkin2", bad_info)


def test_check_fields_rejects_p_mismatch(ca_info_fixture):
    with pytest.raises(CertificateError, match="p/alpha"):
        _check_fields(
            p=ca_info_fixture.p + 1,
            alpha=ca_info_fixture.alpha,
            username="mperkin2",
            public_key=1034503561,
            expected_username="mperkin2",
            ca_info=ca_info_fixture,
        )


def test_check_fields_rejects_alpha_mismatch(ca_info_fixture):
    with pytest.raises(CertificateError, match="p/alpha"):
        _check_fields(
            p=ca_info_fixture.p,
            alpha=ca_info_fixture.alpha + 1,
            username="mperkin2",
            public_key=1034503561,
            expected_username="mperkin2",
            ca_info=ca_info_fixture,
        )


def test_check_fields_rejects_public_key_out_of_range(ca_info_fixture):
    with pytest.raises(CertificateError, match="out of range"):
        _check_fields(
            p=ca_info_fixture.p,
            alpha=ca_info_fixture.alpha,
            username="mperkin2",
            public_key=ca_info_fixture.p,  # must be <= p - 1, this is one over
            expected_username="mperkin2",
            ca_info=ca_info_fixture,
        )


def test_check_fields_accepts_valid_fields(ca_info_fixture):
    _check_fields(
        p=ca_info_fixture.p,
        alpha=ca_info_fixture.alpha,
        username="mperkin2",
        public_key=1034503561,
        expected_username="mperkin2",
        ca_info=ca_info_fixture,
    )
