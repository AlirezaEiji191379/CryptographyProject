from BlockCipherTests.Avalanche.ModerateAvalancheTesterService import ModerateAvalancheTesterService
from BlockCipherTests.Avalanche.StrictAvalancheTesterService import StrictAvalancheTesterService


def plain_text_sac_avalanche_tests_for_block_cipher(key):
    sac_tester_service = StrictAvalancheTesterService("../Avalanche/plaintexts.txt", key, 9, 8, 160)
    sac_matrix, abudance = sac_tester_service.do_sac_test()
    print(sac_matrix)
    print(abudance)


def moderate_avalanche_test(first_text, second_text, key):
    avalanche_tester = ModerateAvalancheTesterService()
    avalanche_tester.get_different_bits_count(first_text, second_text, key)

# plain_text_sac_avalanche_tests_for_block_cipher("alirezaeijialirezaei")

moderate_avalanche_test('0110000101101000011011010110000101100100011000010110100001101101011000010110010001100001011010000110110101100001011001000110000101101000011011010110000101100100',
                        '1110000101101000011011010110000101100100011000010110100001101101011000010110010001100001011010000110110101100001011001000110000101101000011011010110000101100100',
                        '0110101101100101011110010011000101101011011001010111100100110001011010110110010101111001001100010110101101100101011110010011000101101011011001010111100100110001')