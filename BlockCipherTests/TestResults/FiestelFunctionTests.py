from BlockCipherTests.Avalanche.StrictAvalancheTesterService import StrictAvalancheTesterService


def plain_text_sac_avalanche_tests_for_rounds(key):
    f_rounds = 10
    sac_tester_service = StrictAvalancheTesterService("../Avalanche/feisteltexts.txt", key, None, 20)
    sac_matrix, abudance = sac_tester_service.do_sac_test(80)
    print(sac_matrix)
    print(abudance)


plain_text_sac_avalanche_tests_for_rounds("alirezaeijialirezaei")
