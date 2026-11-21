from pathlib import Path

from crypto_client.ca_info import load_ca_info


def test_load_ca_info_reads_p_alpha_and_pem_key():
    info = load_ca_info(Path(__file__).parent.parent.parent / "Pre_installed_CA_information.txt")
    assert info.p == 4294967291
    assert info.alpha == 1000005
    assert info.public_key.key_size == 2048
