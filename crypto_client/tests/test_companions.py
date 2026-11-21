from crypto_client.companions import companion_path


def test_companion_path_appends_suffix_to_base_file_name():
    assert companion_path("report.txt", "enc") == "report.txt.enc"
    assert companion_path("report.txt", "key") == "report.txt.key"
    assert companion_path("report.txt", "hmac") == "report.txt.hmac"
    assert companion_path("report.txt", "hmackey") == "report.txt.hmackey"


def test_companion_path_preserves_directory_component():
    assert companion_path("/home/student/aaa00.wav", "enc") == "/home/student/aaa00.wav.enc"
