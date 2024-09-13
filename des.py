
from numpy import block


class DES:
    __key = None

    # precalc tables 
    #initail permutation
    __ip_table = [
        58, 50, 42, 34, 26, 18, 10, 2,
        60, 52, 44, 36, 28, 20, 12, 4,
        62, 54, 46, 38, 30, 22, 14, 6,
        64, 56, 48, 40, 32, 24, 16, 8,
        57, 49, 41, 33, 25, 17, 9, 1,
        59, 51, 43, 35, 27, 19, 11, 3,
        61, 53, 45, 37, 29, 21, 13, 5,
        63, 55, 47, 39, 31, 23, 15, 7
    ]
    # PC1 permutation table
    __pc1_table = [
        57, 49, 41, 33, 25, 17, 9, 1,
        58, 50, 42, 34, 26, 18, 10, 2,
        59, 51, 43, 35, 27, 19, 11, 3,
        60, 52, 44, 36, 63, 55, 47, 39,
        31, 23, 15, 7, 62, 54, 46, 38,
        30, 22, 14, 6, 61, 53, 45, 37,
        29, 21, 13, 5, 28, 20, 12, 4
    ]
    # Define the left shift schedule for each round
    __shift_schedule = [1, 1, 2, 2,
                      2, 2, 2, 2,
                      1, 2, 2, 2,
                      2, 2, 2, 1]

    # PC2 permutation table
    __pc2_table = [
        14, 17, 11, 24, 1, 5, 3, 28,
        15, 6, 21, 10, 23, 19, 12, 4,
        26, 8, 16, 7, 27, 20, 13, 2,
        41, 52, 31, 37, 47, 55, 30, 40,
        51, 45, 33, 48, 44, 49, 39, 56,
        34, 53, 46, 42, 50, 36, 29, 32
    ]
    #expension
    __e_box_table = [
        32, 1, 2, 3, 4, 5,
        4, 5, 6, 7, 8, 9,
        8, 9, 10, 11, 12, 13,
        12, 13, 14, 15, 16, 17,
        16, 17, 18, 19, 20, 21,
        20, 21, 22, 23, 24, 25,
        24, 25, 26, 27, 28, 29,
        28, 29, 30, 31, 32, 1
    ]

    # S-box tables for DES
    __s_boxes = [
        # S-box 1
        [
            [14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
            [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
            [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
            [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13]
        ],
        # S-box 2
        [
            [15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],
            [3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
            [0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15],
            [13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9]
        ],
        # S-box 3
        [
            [10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8],
            [13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1],
            [13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7],
            [1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12]
        ],
        # S-box 4
        [
            [7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15],
            [13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9],
            [10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4],
            [3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14]
        ],
        # S-box 5
        [
            [2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9],
            [14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6],
            [4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14],
            [11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3]
        ],
        # S-box 6
        [
            [12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11],
            [10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8],
            [9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6],
            [4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13]
        ],
        # S-box 7
        [
            [4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1],
            [13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6],
            [1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2],
            [6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12]
        ],
        # S-box 8
        [
            [13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7],
            [1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2],
            [7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8],
            [2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11]
        ]
    ]
    __p_box_table = [
        16, 7, 20, 21, 29, 12, 28, 17,
        1, 15, 23, 26, 5, 18, 31, 10,
        2, 8, 24, 14, 32, 27, 3, 9,
        19, 13, 30, 6, 22, 11, 4, 25
    ]
    __ip_inverse_table = [
        40, 8, 48, 16, 56, 24, 64, 32,
        39, 7, 47, 15, 55, 23, 63, 31,
        38, 6, 46, 14, 54, 22, 62, 30,
        37, 5, 45, 13, 53, 21, 61, 29,
        36, 4, 44, 12, 52, 20, 60, 28,
        35, 3, 43, 11, 51, 19, 59, 27,
        34, 2, 42, 10, 50, 18, 58, 26,
        33, 1, 41, 9, 49, 17, 57, 25
    ]
    
    def __init__(self, key) -> None:
        self.__key = self.__preprocess_key(key)
         
            
    def __to_binary(self, input) -> str:
        # Converte cada caractere da string em seu valor binário (8 bits para cada caractere)
        return ''.join(f'{ord(c):08b}' for c in input)

    def __add_pad_bits(self, input_bin) -> str:
        if len(input_bin) < 64:
            # Adiciona padding de zeros à direita até atingir o tamanho desejado
            padded_bits = input_bin.ljust(64, '0')
        return padded_bits    
        
    def __preprocess_key(self, key_str):
        key_bin = self.__to_binary(key_str)
        # Adiciona padding bits se necessário
        if len(key_bin) < 64:
            key_bin = self.__add_pad_bits(key_bin)
        # Garante que a chave terá 64 bits
        key_bin = key_bin[:64]
        return key_bin
    
    def __preprocess_message(self, message_str):
        message_bin = self.__to_binary(message_str)        
        # Divide a mensagem em blocos de 64 bits
        blocks = [message_bin[i:i+64] for i in range(0, len(message_bin), 64)]
        # Verifica se o último bloco tem menos de 64 bits e adiciona padding se necessário
        if len(blocks[-1]) < 64:
            blocks[-1] = self.__add_pad_bits(blocks[-1])
        return blocks

    def __generate_subkeys(self):
        if self.__key is None:
            raise ValueError("ERROR: The key cannot be None")
    
        # PC1 permuta a chave inicial
        permuted_key = ''.join(self.__key[i-1] for i in self.__pc1_table)
        
        # Divida a chave permutada em duas metades
        c, d = permuted_key[:28], permuted_key[28:]
        
        subkeys = []
        for round_num in range(16):
            # Aplicar deslocamento
            c = c[self.__shift_schedule[round_num]:] + c[:self.__shift_schedule[round_num]]
            d = d[self.__shift_schedule[round_num]:] + d[:self.__shift_schedule[round_num]]
            # Aplicar PC2
            cd_concatenated = c + d
            subkey = ''.join(cd_concatenated[i-1] for i in self.__pc2_table)
            subkeys.append(subkey)        
        return subkeys
    
    
    # Realiza permutação com base na ip_table
    def __initial_permutation(self, block):
        
        permuted_block = ''.join(block[i-1] for i in self.__ip_table)
        return permuted_block
    
    def __split_block(self, block):
        left_half = block[:32]
        right_half = block[32:]
        return left_half, right_half
    
    def __expand_half(self, half_block):
        expanded_half = ''.join(half_block[i-1] for i in self.__e_box_table)
        return expanded_half
    
    def __substitute(self, block):
        substituted = ''
        for i in range(8):
            segment = block[i*6:(i+1)*6]
            row = int(segment[0] + segment[-1], 2)
            col = int(segment[1:5], 2)
            substituted += f'{self.__s_boxes[i][row][col]:04b}'
        return substituted

    def __feistel_round(self, left, right, subkey):
        # Expande a metade direita
        expanded_right = self.__expand_half(right)
        # XOR com a subchave
        xored = ''.join('1' if expanded_right[i] != subkey[i] else '0' for i in range(48))
        # Substituição com as S-boxes
        substituted = self.__substitute(xored)
        # Permutação P
        permuted = ''.join(substituted[i-1] for i in self.__p_box_table)
        # XOR com a metade esquerda
        new_right = ''.join('1' if permuted[i] != left[i] else '0' for i in range(32))
        return right, new_right
    
    def __inverse_initial_permutation(self, block):
        permuted_block = ''.join(block[i-1] for i in self.__ip_inverse_table)
        return permuted_block 
    
    def __bin_to_ascii(self, binary_str):
        ascii_str = ''.join([chr(int(binary_str[i:i+8], 2)) for i in range(0, len(binary_str), 8)])
        return ascii_str

    def __bin_to_hex(self, binary_str):
        # Convertendo a string binária para inteiro
        decimal_value = int(binary_str, 2)
        # Convertendo o inteiro para hexadecimal, removendo o prefixo '0x'
        hex_value = hex(decimal_value)[2:]
        # Garantindo que a saída seja em letras minúsculas e sem o prefixo '0x'
        return hex_value.zfill(len(binary_str) // 4)  # Cada 4 bits são 1 dígito hexadecimal
    
    def __hex_to_bin(self, hex_str):
        # Convertendo a string hexadecimal para inteiro
        decimal_value = int(hex_str, 16)

        # Convertendo o inteiro para binário, removendo o prefixo '0b'
        bin_value = bin(decimal_value)[2:]

        # Garantindo que o número de bits seja múltiplo de 4 (ou seja, 1 dígito hexadecimal = 4 bits)
        return bin_value.zfill(len(hex_str) * 4)

    def encrypt(self, plaintext):
        blocks = self.__preprocess_message(plaintext)
        subkeys = self.__generate_subkeys()
        ciphertext = ''
        for block in blocks:
            block = self.__initial_permutation(block)
            left, right = self.__split_block(block)
            for subkey in subkeys:
                left, right = self.__feistel_round(left, right, subkey)
            combined_block = right + left
            ciphertext += self.__inverse_initial_permutation(combined_block)
        cipherhex = self.__bin_to_hex(ciphertext)      
        return cipherhex

        
        
    

des = DES("4i20")
out = des.encrypt("Eu amo lolinha")
print(out)
# print(len(out))
        




