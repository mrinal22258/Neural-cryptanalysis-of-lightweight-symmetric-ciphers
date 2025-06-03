import random
from collections import deque
from collections import defaultdict
from collections import Counter
from tqdm import tqdm
import random
import string


# from anytree import Node, RenderTree

# import pandas as pd
# import networkx as nx
# import matplotlib.pyplot as plt






def generate_simon_plaintexts(num_samples=500):
    
    return [(random.randint(0, 0xFFFFFFFF)) for _ in range(num_samples)]





def generate_key_schedule(key, z_sequence, rounds, word_size):
    mod_mask = (1 << word_size) - 1
    m = 4  # Number of key words for m = 4
    k_init = [((key >> (word_size * ((m - 1) - x))) & mod_mask) for x in range(m)]
    k_reg = deque(k_init)
    round_constant = mod_mask ^ 3  # 0xFFFF...FC

    key_schedule = []
    for x in range(rounds):
        rs_3 = ((k_reg[0] << (word_size - 3)) + (k_reg[0] >> 3)) & mod_mask
        rs_3 ^= k_reg[2]
        rs_1 = ((rs_3 << (word_size - 1)) + (rs_3 >> 1)) & mod_mask
        c_z = ((z_sequence >> (x % 62)) & 1) ^ round_constant
        new_k = c_z ^ rs_1 ^ rs_3 ^ k_reg[m - 1]
        key_schedule.append(k_reg.pop())
        k_reg.appendleft(new_k)

    return key_schedule

def feistel_round(x, y, k, word_size):
    mod_mask = (1 << word_size) - 1
    # print(1<<word_size)
    # print(f" the mod mask is {mod_mask}")
    ls_1_x = ((x >> (word_size - 1)) + (x << 1)) & mod_mask
    ls_8_x = ((x >> (word_size - 8)) + (x << 8)) & mod_mask
    ls_2_x = ((x >> (word_size - 2)) + (x << 2)) & mod_mask
    # print(ls_1_x)
    xor_1 = (ls_1_x & ls_8_x) ^ y
    xor_2 = xor_1 ^ ls_2_x
    new_x = k ^ xor_2
    
    return new_x, x


def encrypt(plaintext, key_schedule, rounds, word_size):
    mod_mask = (1 << word_size) - 1
    x = (plaintext >> word_size) & mod_mask
    y = plaintext & mod_mask 

    for k in key_schedule:
        x, y = feistel_round(x, y, k, word_size)

    return (x << word_size) + y


def encrypt2(plaintext, key_schedule, rounds, word_size, delta_x):
    mod_mask = (1 << word_size) - 1
    x = (plaintext >> word_size) & mod_mask
    y = plaintext & mod_mask 

    for k in key_schedule:

        y = y ^ delta_x
        x, y = feistel_round(x, y, k, word_size)


    sz = len(bin(x))-2
    newwordsize = 16-sz + word_size
    return (x << newwordsize) + y




def decrypt(ciphertext, key_schedule, rounds, word_size):
    mod_mask = (1 << word_size) - 1
    x = (ciphertext >> word_size) & mod_mask
    y = ciphertext & mod_mask

    for k in reversed(key_schedule):
        y, x = feistel_round(y, x, k, word_size)

    return (x << word_size) + y

def generate_random_plaintexts(count, block_size):
    plaintexts = [random.randint(0, (1 << block_size) - 1) for _ in range(count)]
    return plaintexts

def save_plaintexts_and_ciphertexts_to_file(plaintexts, key_schedule, rounds, word_size, filename):
    with open(filename, 'w') as file:
        for pt in plaintexts:
            ct = encrypt(pt, key_schedule, rounds, word_size)
            file.write(f"{bin(pt)[2:].zfill(word_size * 2)} {bin(ct)[2:].zfill(word_size * 2)}\n")

def find_patterns(plaintexts, key_schedule, rounds, word_size):
    patterns = []
    for pt in plaintexts:
        ct = encrypt(pt, key_schedule, rounds, word_size)
        pattern = [[(pt >> i) & 1 for i in range(word_size * 2)], [(ct >> j) & 1 for j in range(word_size * 2)]]
        patterns.append(pattern)
    return patterns

def analyze_patterns(patterns, output_file):
    with open(output_file, 'w') as file:
        for pattern in patterns:
            pt_bits, ct_bits = pattern
            pt_str = ''.join(map(str, reversed(pt_bits)))
            ct_str = ''.join(map(str, reversed(ct_bits)))
            file.write(f"{pt_str} -> {ct_str}\n")











def main():
    # Parameters for Simon cipher
    n = 32  # Block size
    m = 4   # Number of key words
    z = 0b01100111000011010100100010111110110011100001101010010001011111  # z0 sequence
    key_size = n  # Key size
    word_size = n // 2
    rounds = 5  # Reduced number of rounds for pattern analysis
#  0-0 :  (11 : 2454) (01 : 2456) (00 : 2492) (10 : 2598) -> 5  
#0-0 :  (10 : 2529) (11 : 2464) (00 : 2530) (01 : 2477)   ->32
    # Example key
    # key = 0x1918111009080100
    key  =0x0123456789abcdef
    plan = 0x00ff00ff

    # Generate key schedule
    key_schedule = generate_key_schedule(key, z, rounds, word_size)

    # Generate plaintexts
    block_size = n  # Block size in bits
    plaintexts = generate_random_plaintexts(1, block_size)
    filename = "PlainAndCipher.txt"

    '''         # TODO : TASK 1 --  00-01-2025          '''  
    # save_plaintexts_and_ciphertexts_to_file(plaintexts, key_schedule, rounds, word_size, filename)

    # print(len(plaintexts))
    # # # Find patterns
    # # patterns = find_patterns(plaintexts, key_schedule, rounds, word_size)

    # # Analyze and save patterns
    # # analyze_patterns(patterns, "patterns_analysis.txt")
    # # print("Pattern analysis saved to patterns_analysis.txt")
    # cipherList = []
    # with open("PlainAndCipher.txt", 'r') as f: # Replace "cipher_data.txt" with the file name
    #     for line in f.readlines():
    #         columns = line.strip().split()  # Split each line into columns
    #         if len(columns) == 2:  # Ensure there are exactly two columns
    #             cipherList.append(columns[1])
    # # print(cipherList)


    
    # pattern = defaultdict(list)
    # i = 0
    # with open("PlainAndCipher.txt",'r') as f:
    #     # print(f.readlines())
    #     for line in f.readlines(): 
    #         i+=1
    #         columns = line.strip().split()
    #         plain = columns[0]
    #         cipher = columns[1]
 
    #         for ind, e in enumerate(plain):         
    #             for index , x in enumerate(cipher):
    #                 pattern[f"{ind}-{index}"].append(f"{e}{x}")

             
    # for key , value in pattern.items():
    #     cnt = Counter(value)
    #     pattern[key] = cnt

    # # print(pattern)
    
    # ''' FOR BETTER VISUAL REPRESENTATION '''
    # # root = Node("Root")

    # # for key, sub_dict in pattern.items():
    # #     parent = Node(key, parent=root)
    # #     for sub_key, count in sub_dict.items():
    # #         Node(f"{sub_key}: {count}", parent=parent)

    # # for pre, _, node in RenderTree(root):
    # #     print(f"{pre}{node.name}")

       

    # # rows = []
    # # for key, sub_dict in pattern.items():
    # #     for sub_key, count in sub_dict.items():
    # #         rows.append((key, sub_key, count))

    # # df = pd.DataFrame(rows, columns=["Key", "Sub-Key", "Count"])
    # # print(df)

    # # G = nx.DiGraph()

    # # for key, sub_dict in pattern.items():
    # #     for sub_key, count in sub_dict.items():
    # #         G.add_edge(key, sub_key, weight=count)

    # # pos = nx.spring_layout(G)
    # # nx.draw(G, pos, with_labels=True, node_size=2000, node_color="lightblue")
    # # labels = nx.get_edge_attributes(G, "weight")
    # # nx.draw_networkx_edge_labels(G, pos, edge_labels=labels)
    # # plt.show()

    # try:
    #     with open("Visual.txt", 'w') as file:
    #         for key, values in pattern.items():
    #             file.write(f"{key} : ")
    #             for cnt_key , cnt_value in values.items():
    #                 file.write(f" ({cnt_key} : {cnt_value})")

    #             file.write("\n")
    #     print(f"Dictionary written successfully.")
    # except Exception as e:
    #     print(f"An error occurred: {e}")


    '''         # TODO : TASK 2 --  00-01-2025          '''  

    # rounds = 5
    # # bit_combinations = [format(i, '016b') for i in range(2**16)]
    # # delta_x = [format(int(b, 2), '016X') for b in bit_combinations]  # Hexadecimal representation
    # delta_x = [i for i in range(1,(2**16)+1)]
    # # print(type(delta_x[0]))  # This is a string

    # deltax_cipher = [] 
    # i = 0
    # for deltax in delta_x:
    #     if i == 1:break
    #     cipher = encrypt2(plan, key_schedule, rounds, word_size , deltax)  # Pass hex string
    #     deltax_cipher.append(cipher)
    #     i+=1
    
    # print(deltax_cipher[:4])
    
    # deltay2 = []
    # for ind , cipher in enumerate(deltax_cipher):
    #     bin_cipher = bin(cipher)[2:]
    #     if ind == 7: break
    #     if ind == 1 :
    #         print(len(bin_cipher))
    #         print(cipher)
    #     c2 = bin_cipher[:16]
    #     c2_ = bin_cipher[16:]
    #     # print(len(c2))
    #     # print(len(c2_))
    #     print(len(bin_cipher ))
    #     delta_y2 = int(c2) ^ int(c2_)

    #     deltay2.append(delta_y2)
    # print(deltax_cipher[:5])
    # print(deltay2[:5])    



    '''         # TODO : TASK 3 --  05-02-2025          '''   
    
    '''ERRORS FOUND - SOMETHING WRONG WHILE TAKING DELTA X 20597 . NUMBER OF BITS FOUNDS  LESS .'''

    plan = 0x00ff00ff
    key  =0x0123456789abcdef
    simon_plaintexts = generate_simon_plaintexts()
    
    
   
    rounds = 5
    word_size = 16
    delta_x = [i for i in range(0,(1000))]
    key_schedule = generate_key_schedule(key, z, rounds, word_size)

    ciphersForAllPlaintexts = [[] for _ in range(1000)]

    for plantext in tqdm(simon_plaintexts, colour="green"):
        deltax_cipher = [] 
        for deltax in delta_x:
            c1_c2_ = encrypt2(plantext, key_schedule, rounds, word_size , deltax)  # Pass hex string
            deltax_cipher.append(c1_c2_)

        deltay2 = []

        for ind  in (range(len(deltax_cipher))):
            bin_cipher = bin(deltax_cipher[ind])[2:]

         
    
            c2 = bin_cipher[:16]
            c2_ = bin_cipher[16:]


            try:
                c2 = int(c2, 2)
                c2_= int(c2_, 2)
                delta_y2 = c2 ^ c2_
                delta_y2 = bin(delta_y2)[2:].zfill(16)
                if(len(delta_y2 ) != 16) : 
                    print("ERROR THE BIT LENGTH OF DELTA Y2 IS NOT 16")
                deltay2.append(delta_y2)

            except ValueError:
                # print()
                # print(f"Error Found at {ind} and c2_ is {bin_cipher} ")
                pass
                

         
        c1c2 = encrypt(plantext , key_schedule, rounds , word_size)
        c1c2xorc2_c2_ = []
       
        for c1_c2_ in deltax_cipher:
            xor = c1c2 ^ c1_c2_
            xor= bin(xor)[2:].zfill(32)
            c1c2xorc2_c2_.append(xor)

        if len(c1c2xorc2_c2_) != 1000: 
            print("ERROR IN PLAIN TEXT {plantext}")
            continue
       
        for i in range(1000):
            ciphersForAllPlaintexts[i].append(c1c2xorc2_c2_[i])

        



    with open("./task3.txt","w") as f:
        for i in range(1000):
            deltax = bin(i)[2:].zfill(16)
            f.write(f" {deltax}  :  ")
            cnter = Counter(ciphersForAllPlaintexts[i])
       
            val_based_rev  = {k: v for k , v in sorted(cnter.items(),key = lambda item: item[1],reverse=True)}
            # break
            for key , value in val_based_rev.items():
                f.write(f" ( {key} : {value} )")
            f.write(" \n")

    

    print("Done ")
   
if __name__ == "__main__":
    main()

 