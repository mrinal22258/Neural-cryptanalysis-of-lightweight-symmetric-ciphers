import random
from collections import deque

class SPECK32:
    def __init__(self, key, word_size, rounds, alpha=7, beta=2):
        self.word_size = word_size
        self.rounds = rounds
        self.alpha = alpha
        self.beta = beta
        self.mod_mask = (1 << word_size) - 1
        self.key_schedule = self._generate_key_schedule(key)

    def _rol(self, x, r):
        return ((x << r) | (x >> (self.word_size - r))) & self.mod_mask

    def _ror(self, x, r):
        return ((x >> r) | (x << (self.word_size - r))) & self.mod_mask

    def _generate_key_schedule(self, key):
        m = 4  # Number of key words for SPECK32/64
        l = [((key >> (self.word_size * i)) & self.mod_mask) for i in range(1, m)]
        k = key & self.mod_mask
        key_schedule = [k]

        for i in range(self.rounds - 1):
            r_l = self._ror(l[i], self.alpha)
            l_val = (r_l + key_schedule[i]) & self.mod_mask
            l_val ^= i
            r_k = self._rol(key_schedule[i], self.beta)
            k_val = r_k ^ l_val
            l.append(l_val)
            key_schedule.append(k_val)

        return key_schedule

    def _round(self, x, y, k):
        x = self._ror(x, self.alpha)
        x = (x + y) & self.mod_mask
        x ^= k
        y = self._rol(y, self.beta)
        y ^= x
        return x, y

    def _inverse_round(self, x, y, k):
        y ^= x
        y = self._ror(y, self.beta)
        x ^= k
        x = (x - y) & self.mod_mask
        x = self._rol(x, self.alpha)
        return x, y

    def encrypt(self, plaintext):
        x = (plaintext >> self.word_size) & self.mod_mask
        y = plaintext & self.mod_mask
        for k in self.key_schedule:
            x, y = self._round(x, y, k)
        return (x << self.word_size) | y

    def decrypt(self, ciphertext):
        x = (ciphertext >> self.word_size) & self.mod_mask
        y = ciphertext & self.mod_mask
        for k in reversed(self.key_schedule):
            x, y = self._inverse_round(x, y, k)
        return (x << self.word_size) | y

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
            pattern = [[(pt >> i) & 1 for i in range(self.word_size * 2)],
                       [(ct >> j) & 1 for j in range(self.word_size * 2)]]
            patterns.append(pattern)
        return patterns

    def analyze_patterns(self, patterns, output_file):
        with open(output_file, 'w') as file:
            for pattern in patterns:
                pt_bits, ct_bits = pattern
                pt_str = ''.join(map(str, reversed(pt_bits)))
                ct_str = ''.join(map(str, reversed(ct_bits)))
                file.write(f"{pt_str} -> {ct_str}\n")