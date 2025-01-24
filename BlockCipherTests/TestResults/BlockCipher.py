from BlockCipherTests.Avalanche.StrictAvalancheTesterService import StrictAvalancheTesterService


def plain_text_sac_avalanche_tests_for_block_cipher(key):
    sac_tester_service = StrictAvalancheTesterService("../Avalanche/plaintexts.txt", key, 16, 10, 160)
    sac_matrix, abudance = sac_tester_service.do_sac_test()
    print(sac_matrix)
    print(abudance)



plain_text_sac_avalanche_tests_for_block_cipher("alirezaeijialirezaei")
