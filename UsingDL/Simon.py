import random
from collections import deque

class SIMON32:
    def __init__(self, key, word_size, rounds, z_sequence=0b01100111000011010100100010111110110011100001101010010001011111 ):
        self.word_size = word_size
        self.rounds = rounds
        self.z_sequence = z_sequence
        self.mod_mask = (1 << word_size) - 1
        self.key_schedule = self._generate_key_schedule(key)

    def _generate_key_schedule(self, key):
        m = 4  # Number of key words for m = 4
        k_init = [((key >> (self.word_size * ((m - 1) - x))) & self.mod_mask) for x in range(m)]
        k_reg = deque(k_init)
        round_constant = self.mod_mask ^ 3  # 0xFFFF...FC

        key_schedule = []
        for x in range(self.rounds):
            rs_3 = ((k_reg[0] << (self.word_size - 3)) + (k_reg[0] >> 3)) & self.mod_mask
            rs_3 ^= k_reg[2]
            rs_1 = ((rs_3 << (self.word_size - 1)) + (rs_3 >> 1)) & self.mod_mask
            c_z = ((self.z_sequence >> (x % 62)) & 1) ^ round_constant
            new_k = c_z ^ rs_1 ^ rs_3 ^ k_reg[m - 1]
            key_schedule.append(k_reg.pop())
            k_reg.appendleft(new_k)

        return key_schedule

    def _feistel_round(self, x, y, k):
        ls_1_x = ((x >> (self.word_size - 1)) + (x << 1)) & self.mod_mask
        ls_8_x = ((x >> (self.word_size - 8)) + (x << 8)) & self.mod_mask
        ls_2_x = ((x >> (self.word_size - 2)) + (x << 2)) & self.mod_mask
        xor_1 = (ls_1_x & ls_8_x) ^ y
        xor_2 = xor_1 ^ ls_2_x
        new_x = k ^ xor_2
        return new_x, x

    def encrypt(self, plaintext):
        x = (plaintext >> self.word_size) & self.mod_mask
        y = plaintext & self.mod_mask
        for k in self.key_schedule:
            x, y = self._feistel_round(x, y, k)
        return (x << self.word_size) + y

    def encrypt2(self, plaintext, delta_x):
        x = (plaintext >> self.word_size) & self.mod_mask
        y = plaintext & self.mod_mask 
        for k in self.key_schedule:
            y = y ^ delta_x
            x, y = self._feistel_round(x, y, k)
        sz = len(bin(x)) - 2
        newwordsize = 16 - sz + self.word_size
        return (x << newwordsize) + y

    def decrypt(self, ciphertext):
        x = (ciphertext >> self.word_size) & self.mod_mask
        y = ciphertext & self.mod_mask
        for k in reversed(self.key_schedule):
            y, x = self._feistel_round(y, x, k)
        return (x << self.word_size) + y

    @staticmethod
    def generate_random_plaintexts(count, block_size):
        return [random.randint(0, (1 << block_size) - 1) for _ in range(count)]

    def save_plaintexts_and_ciphertexts(self, plaintexts, filename):
        with open(filename, 'w') as file:
            for pt in plaintexts:
                ct = self.encrypt(pt)
                file.write(f"{bin(pt)[2:].zfill(self.word_size * 2)} {bin(ct)[2:].zfill(self.word_size * 2)}\n")

    def find_patterns(self, plaintexts):
        patterns = []
        for pt in plaintexts:
            ct = self.encrypt(pt)
            pattern = [[(pt >> i) & 1 for i in range(self.word_size * 2)], [(ct >> j) & 1 for j in range(self.word_size * 2)]]
            patterns.append(pattern)
        return patterns

    def analyze_patterns(self, patterns, output_file):
        with open(output_file, 'w') as file:
            for pattern in patterns:
                pt_bits, ct_bits = pattern
                pt_str = ''.join(map(str, reversed(pt_bits)))
                ct_str = ''.join(map(str, reversed(ct_bits)))
                file.write(f"{pt_str} -> {ct_str}\n")





# Example usage:
if __name__ == "__main__":
    n = 32  
    m = 4   
    z = 0b01100111000011010100100010111110110011100001101010010001011111  # z0 sequence
    key_size = n  #
    word_size = n // 2
    rounds = 5
    key  =0x0123456789abcdef
    simon = SIMON32(key , word_size , rounds,  z )
    plaintext = 0x00ff00ff  #
    ciphertext = simon.encrypt(plaintext)
    decrypted = simon.decrypt(ciphertext)
    
    print(f"Plaintext: {plaintext}")
    print(f"Ciphertext: {ciphertext}")
    print(f"Decrypted: {decrypted}")




    # word_size = 16
    # key = 0x1918111009080100  # 64-bit key
    # rounds = 32
    # speck = SPECK32(key, word_size, rounds)

    # plaintext = 0x6574  # Example 32-bit plaintext (high=0x65, low=0x74)
    # ciphertext = speck.encrypt(plaintext)
    # decrypted = speck.decrypt(ciphertext)

    # print(f"Plaintext:  {hex(plaintext)}")
    # print(f"Ciphertext: {hex(ciphertext)}")
    # print(f"Decrypted:  {hex(decrypted)}")
