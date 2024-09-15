# Algoritmo DES (Data Encryption Standard) em Python

## Introdução

Este código foi implementado **para fins educacionais**, com o objetivo de demonstrar como o **DES** funciona internamente. Ele mostra o processo de criptografia e descriptografia, mas **não foi testado para uso em produção** e **não deve ser utilizado para garantir segurança real**. O DES foi substituído por algoritmos mais seguros, como o **AES**, devido a vulnerabilidades inerentes ao tamanho da chave e às capacidades computacionais modernas.

O DES é um algoritmo de criptografia simétrica que opera em blocos de 64 bits de dados, utilizando uma chave de 64 bits para aplicar um processo iterativo de 16 rodadas. Este processo envolve permutações, substituições através de S-Boxes, e operações de XOR.

## Preprocessamento da Chave e da Mensagem no Algoritmo DES

No **DES**, tanto a chave de criptografia quanto a mensagem precisam passar por um **preprocessamento** antes de serem usadas no processo de criptografia. Esse preprocessamento garante que os dados estejam no formato correto (binário) e no comprimento adequado (64 bits), permitindo que o algoritmo funcione corretamente.

#### 1. **Preprocessamento da Chave (`__preprocess_key`)**

O método `__preprocess_key` transforma a chave fornecida em uma string binária de 64 bits. O DES exige uma chave de exatamente 64 bits, e esse método garante que qualquer chave de entrada atenda a essa exigência, realizando os seguintes passos:

```python
def __preprocess_key(self, key_str):
    key_bin = self.__to_binary(key_str)  # Converte a chave para binário
    if len(key_bin) < 64:
        key_bin = self.__add_pad_bits(key_bin)  # Adiciona padding se necessário
    key_bin = key_bin[:64]  # Garante que a chave terá exatamente 64 bits
    return key_bin
```

---

#### 2. **Preprocessamento da Mensagem (`__preprocess_message`)**

O método `__preprocess_message` divide a entrada em blocos de 64 bits e garante que o último bloco, se não for completo, seja preenchido com zeros (padding). Isso permite que o DES criptografe a mensagem corretamente, bloco por bloco.

```python
def __preprocess_message(self, message_str):
    message_bin = self.__to_binary(message_str)  # Converte a mensagem para binário
    blocks = [message_bin[i:i+64] for i in range(0, len(message_bin), 64)]  # Divide a mensagem em blocos de 64 bits
    if len(blocks[-1]) < 64:
        blocks[-1] = self.__add_pad_bits(blocks[-1])  # Adiciona padding no último bloco, se necessário
    return blocks
```

## Estrutura e Funcionamento do DES

### 1. **Permutação Inicial (IP)**

A primeira etapa do DES envolve a **permutação inicial** (IP), que reorganiza os bits do bloco de entrada de 64 bits. A tabela **IP** é pré-definida e serve para aumentar a complexidade do sistema.

No código, isso é implementado no método `__initial_permutation`:

```python
def __initial_permutation(self, block):
    permuted_block = ''.join(block[i-1] for i in self.__ip_table)
    return permuted_block
```

#### Conceito:

- O bloco de 64 bits passa por uma permutação, onde os bits são reordenados de acordo com uma tabela fixa. Isso não adiciona segurança, mas é um passo fundamental no processo de DES, já que a estrutura Feistel depende de bit-shuffling.

### 2. **Divisão do Bloco**

Após a permutação inicial, o bloco é dividido em duas metades de 32 bits: uma metade **esquerda (L)** e uma metade **direita (R)**.

No código, a divisão é feita assim:

```python
def __split_block(self, block):
    left_half = block[:32]
    right_half = block[32:]
    return left_half, right_half
```

#### Conceito:

- O bloco é dividido para que o algoritmo Feistel possa operar em metades menores, alternando o processamento entre elas.

### 3. **Rodadas Feistel (16 Rodadas)**

A estrutura Feistel é o coração do DES. Em cada uma das 16 rodadas, a metade direita do bloco é expandida, combinada com uma subchave, passa por substituições nas **S-Boxes**, e é permutada antes de ser combinada com a metade esquerda. O código que executa uma rodada Feistel é o seguinte:

```python
def __feistel_round(self, left, right, subkey):
    expanded_right = self.__expand_half(right)  # Expansão de 32 para 48 bits
    xored = ''.join('1' if expanded_right[i] != subkey[i] else '0' for i in range(48))  # XOR com subchave
    substituted = self.__substitute(xored)  # Substituições pelas S-Boxes
    permuted = ''.join(substituted[i-1] for i in self.__p_box_table)  # Permutação com a P-Box
    new_right = ''.join('1' if permuted[i] != left[i] else '0' for i in range(32))  # XOR com a metade esquerda
    return right, new_right  # Troca das metades
```

#### Explicação das Subetapas:

1. **Expansão (E-Box)**:
   A metade direita (32 bits) é expandida para 48 bits para que possa ser combinada com a subchave de 48 bits. Isso é feito com o método `__expand_half`.

   ```python
   def __expand_half(self, half_block):
       expanded_half = ''.join(half_block[i-1] for i in self.__e_box_table)
       return expanded_half
   ```

   **Conceito**: A expansão permite que a subchave seja aplicada. A expansão também cria redundância nos bits, o que ajuda a misturar os dados durante a criptografia.

2. **Operação XOR com Subchave**:
   O resultado da expansão é combinado com uma subchave gerada para aquela rodada, utilizando a operação **XOR**.

   **Conceito**: O XOR é uma operação fundamental em criptografia, pois é reversível. Isso permite que, durante a descriptografia, a operação XOR com a mesma subchave reverta o processo.

3. **Substituições (S-Boxes)**:
   O bloco de 48 bits resultante do XOR é dividido em 8 partes de 6 bits. Cada parte passa por uma **caixa de substituição (S-Box)**, que mapeia os 6 bits de entrada para 4 bits de saída. Isso é feito com o método `__substitute`.

   ```python
   def __substitute(self, block):
       substituted = ''
       for i in range(8):
           segment = block[i*6:(i+1)*6]
           row = int(segment[0] + segment[-1], 2)
           col = int(segment[1:5], 2)
           substituted += f'{self.__s_boxes[i][row][col]:04b}'
       return substituted
   ```

   **Conceito**: As S-Boxes introduzem não-linearidade no sistema, tornando o DES resistente a ataques simples de análise linear.

4. **Permutação (P-Box)**:
   O resultado da substituição é permutado utilizando uma tabela de permutação **P-Box** para misturar ainda mais os bits.

   **Conceito**: A permutação embaralha os bits para garantir que os efeitos de mudanças em um bit se propaguem ao longo de todo o bloco.

5. **Combinação com a Metade Esquerda**:
   A metade direita processada é combinada com a metade esquerda usando XOR, e as metades são trocadas.

   **Conceito**: A troca das metades a cada rodada é uma característica da estrutura Feistel, essencial para que o processo de criptografia possa ser revertido na descriptografia.

### 4. **Permutação Inversa (IP-1)**

Após as 16 rodadas Feistel, as metades resultantes são recombinadas e passam por uma permutação inversa (IP-1), que reorganiza os bits na ordem correta.

```python
def __inverse_initial_permutation(self, block):
    permuted_block = ''.join(block[i-1] for i in self.__ip_inverse_table)
    return permuted_block
```

#### Conceito:

- A permutação inversa é a última etapa que reorganiza os bits do bloco para gerar a saída final criptografada.

### 5. **Geração de Subchaves**

As subchaves usadas nas rodadas Feistel são geradas a partir da chave original de 64 bits. A chave é permutada e dividida em duas metades, e em cada rodada essas metades são deslocadas e combinadas para gerar subchaves de 48 bits.

```python
def __generate_subkeys(self):
    permuted_key = ''.join(self.__key[i-1] for i in self.__pc1_table)  # PC1 Permutação
    c, d = permuted_key[:28], permuted_key[28:]  # Dividir a chave em duas metades
    subkeys = []
    for round_num in range(16):
        c = c[self.__shift_schedule[round_num]:] + c[:self.__shift_schedule[round_num]]  # Deslocamento circular
        d = d[self.__shift_schedule[round_num]:] + d[:self.__shift_schedule[round_num]]
        cd_concatenated = c + d
        subkey = ''.join(cd_concatenated[i-1] for i in self.__pc2_table)  # PC2 Permutação
        subkeys.append(subkey)
    return subkeys
```

#### Conceito:

- As subchaves são derivadas da chave original através de permutações e deslocamentos. Cada rodada utiliza uma subchave única para garantir que o processo seja não-linear e resistente a ataques.

## Criptografia e Descriptografia

Os métodos **`encrypt`** e **`decrypt`** são os principais responsáveis pelo processo de criptografia e descriptografia no algoritmo DES.

### Método `encrypt(plaintext: str) -> str`

O método `encrypt` é responsável por criptografar uma mensagem de texto em claro. Ele faz isso dividindo a mensagem em blocos de 64 bits e aplicando o algoritmo DES em cada um desses blocos.

#### Passo a Passo do Método `encrypt`

```python
def encrypt(self, plaintext):
    blocks = self.__preprocess_message(plaintext)  # 1. Preprocessa a mensagem em blocos de 64 bits
    subkeys = self.__generate_subkeys()  # 2. Gera 16 subchaves a partir da chave de 64 bits
    ciphertext = ''  # 3. Inicializa a variável para armazenar o texto criptografado
    for block in blocks:  # 4. Processa cada bloco da mensagem
        block = self.__initial_permutation(block)  # 5. Aplica a permutação inicial (IP)
        left, right = self.__split_block(block)  # 6. Divide o bloco em metade esquerda e direita
        for subkey in subkeys:  # 7. Executa 16 rodadas Feistel
            left, right = self.__feistel_round(left, right, subkey)  # Rodada Feistel com subchave
        combined_block = right + left  # 8. Combina as metades invertidas
        ciphertext += self.__inverse_initial_permutation(combined_block)  # 9. Aplica a permutação inversa (IP-1)
    cipherhex = self.__bin_to_hex(ciphertext)  # 10. Converte o binário criptografado para hexadecimal
    return cipherhex  # 11. Retorna o texto criptografado em hexadecimal
```

### Método `decrypt(ciphertext: str) -> str`

O método `decrypt` faz o processo inverso do método `encrypt`. Ele recebe um texto criptografado em formato hexadecimal, converte-o para binário e aplica o processo inverso das 16 rodadas Feistel, restaurando a mensagem original.

#### Passo a Passo do Método `decrypt`

```python
def decrypt(self, hex):
    blocks = self.__hex_to_bin(hex)  # 1. Converte o texto criptografado de hexadecimal para binário
    blocks = [blocks[i:i+64] for i in range(0, len(blocks), 64)]  # 2. Divide o binário em blocos de 64 bits
    subkeys = self.__generate_subkeys()[::-1]  # 3. Gera as subchaves e inverte a ordem para descriptografia
    decrypted_bin = ''  # 4. Inicializa a variável para armazenar o texto descriptografado
    for block in blocks:  # 5. Processa cada bloco criptografado
        block = self.__initial_permutation(block)  # 6. Aplica a permutação inicial (IP)
        left, right = self.__split_block(block)  # 7. Divide o bloco em metade esquerda e direita
        for subkey in subkeys:  # 8. Executa as 16 rodadas Feistel na ordem inversa
            left, right = self.__feistel_round(left, right, subkey)  # Rodada Feistel com subchave invertida
        combined_block = right + left  # 9. Combina as metades invertidas
        decrypted_bin += self.__inverse_initial_permutation(combined_block)  # 10. Aplica a permutação inversa (IP-1)
    decrypted_text = self.__bin_to_ascii(decrypted_bin)  # 11. Converte o binário descriptografado para ASCII
    return decrypted_text  # 12. Retorna o texto descriptografado
```

## Demonstração: Criptografia e Descriptografia com a Classe DES

```python
# Importa a classe DES
from des import DES

# Passo 1: Criar uma instância da classe DES com uma chave
key = "minha123"  # Exemplo de chave
des = DES(key)  # Instancia o DES com a chave

# Passo 2: Definir a mensagem que será criptografada
plaintext = "Mensagem secreta"

# Passo 3: Criptografar a mensagem
encrypted_message = des.encrypt(plaintext)
print(f"Mensagem criptografada: {encrypted_message}")

# Passo 4: Descriptografar a mensagem
decrypted_message = des.decrypt(encrypted_message)
print(f"Mensagem descriptografada: {decrypted_message}")
```

### Saída

```bash
Mensagem criptografada: a6f3c1d8e5b3c6a1  # Exemplo de texto criptografado em hexadecimal
Mensagem descriptografada: Mensagem secreta
```
