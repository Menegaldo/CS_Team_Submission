# Tarefa1 — Writeup

###### Resolvido por @Menegaldo

> Este é um CTF sobre [Reverse Engineering]


---

## Sobre o desafio

- Binário recebido: `tarefa1`
    
- Comportamento: pede `Citizen Access ID: Entrada correta > ACCESS GRANTED > impressa a flag.

---

## Resolução

### Análise Inicial:

Com o arquivo em mão, primeiro passo é identificar o que ele é:

<img width="722" height="81" alt="image" src="https://github.com/user-attachments/assets/6c279216-3344-463e-8935-12515da56be6" />

Ele é um arquivo executável linux ELF 64-bits, com isso, podemos rodar ele no terminal:

<img width="943" height="452" alt="image" src="https://github.com/user-attachments/assets/72787545-2508-4ed3-badc-46fb33cfb716" />

Com isso, vemos que é um arquivo que tem uma interface de interação e tem um campo de entrada, quando colocado qualquer informação temos uma saída:

```
[!] ACCESS DENIED - Invalid Citizen ID
[-] Session Terminated
```

Logo, se colocar o Citizen ID correto teremos a flag desejada.

---

### Desenvolvimento:

Analisando o código é possível analisar que ele está ofuscado com UPX:

<img width="948" height="131" alt="image" src="https://github.com/user-attachments/assets/d8d72d9b-e206-4553-b6b0-d579c41b1fb3" />

Desempacotando o arquivo ``tarefa1`` teremos o ``tarefa1_unpacked``, analisando esse arquivo no radare2 podemos tirar algumas conclusões:

<img width="563" height="765" alt="image" src="https://github.com/user-attachments/assets/577e742c-47ce-4a5c-b50e-181212ec0783" />

Temos as seguintes funções dentro do executável. Localizando a função ``sym.imp.getchar``:

<img width="616" height="51" alt="image" src="https://github.com/user-attachments/assets/008e2398-2ac4-43cb-b26c-52de4e4c7829" />

Analisando a função ``sym.imp.getchar``:

```
[0x00400900]> pd 96 @ 0x4030a4          # desasm em torno do call getchar
            0x004030a4      e8f7d7ffff     call sym.imp.getchar        ; int getchar(void)                                                                        
            0x004030a9      89c6           mov esi, eax
            0x004030ab      488b85c0a0..   mov rax, qword [rbp - 0x65f40]
	        ... (código dentro da função)
            0x0040324b      69c8a5050000   imul ecx, eax, 0x5a5
[0x00400900]> 
```

Dentro da função ``sym.imp.getchar`` é onde foi mapeada a permutação.

Com essas informações em mãos, vamos iniciar a analise em tempo de execução:

<img width="729" height="411" alt="image" src="https://github.com/user-attachments/assets/02a73687-17e3-4993-b595-0a91ea7a9fd1" />

Como o código está rodando a medida que nós avançamos, teremos:

<img width="708" height="276" alt="image" src="https://github.com/user-attachments/assets/350552f9-e463-4cd7-a7de-f7ca22935639" />

Para ajudar a mapear o que está sendo comparado para printar a flag, vamos usar a seguinte string:

```
ABCDEFGHIJKLMNOPQRS
```

Com isso, vamos analisar a cada ponto:

```
dr rsi    # índice/offset destino usado pela VM
dr edx    # byte lido (ASCII)
dc
````

Teremos a seguinte resposta:

<img width="705" height="136" alt="image" src="https://github.com/user-attachments/assets/644e63ed-e387-4871-b923-821e9e21b088" />

Fazendo isso para todos os caracteres, teremos a sequência mapeada:

```
A(0x41) -> rsi = 7
B(0x42) -> rsi = 8
C(0x43) -> rsi = 13
D(0x44) -> rsi = 15
E(0x45) -> rsi = 16
F(0x46) -> rsi = 26
G(0x47) -> rsi = 27
H(0x48) -> rsi = 22
I(0x49) -> rsi = 21
J(0x4A) -> rsi = 4
K(0x4B) -> rsi = 18
L(0x4C) -> rsi = 28
M(0x4D) -> rsi = 23
N(0x4E) -> rsi = 29
O(0x4F) -> rsi = 9
P(0x50) -> rsi = 1
Q(0x51) -> rsi = 25
R(0x52) -> rsi = 30
S(0x53) -> rsi = 17
```

Depois de mapeada a permutação dos índices, a próxima parte da análise mostra como o programa valida o `Citizen ID`.  

A entrada do usuário é reorganizada nessa ordem fixa:

```
perm = [7,8,13,15,16,26,27,22,21,4,18,28,23,29,9,1,25,30,17]
```

Ou seja, o **primeiro caractere digitado** vai para a posição `7` do buffer interno, o segundo para `8`, o terceiro para `13`, e assim por diante.

Na sequência, a VM aplica operações aritméticas e lógicas entre os caracteres rearranjados e compara com valores constantes.  

Um exemplo identificado é:

```
(buf[14] * buf[6]) * ((buf[12] - buf[10]) ^ buf[13]) == 0x3fcf
```

Essas equações são espalhadas pelo binário e garantem que somente uma combinação exata de caracteres passará por todas elas.

Para resolver todas essas equações manualmente seria inviável. A abordagem eficiente é **modelar o problema em um solver SMT** (como o Z3).

Passos no script:

1. Declarar cada posição do buffer como variável de 8 bits (`BitVec`).
2. Restringir para o intervalo de caracteres ASCII printáveis (`32 <= c <= 126`).
3. Adicionar todas as equações extraídas da execução da VM.
4. Pedir para o solver encontrar uma solução satisfatória.
5. Reconstruir a string de acordo com a ordem de permutação.

Exemplo (esqueleto do solver em Python):

```python
from z3 import *

solver = Solver()
perm = [7,8,13,15,16,26,27,22,21,4,18,28,23,29,9,1,25,30,17]
flag = {i: BitVec(f"c_{i}", 8) for i in perm}

# Restringe para ASCII printável
for i in perm:
    solver.add(flag[i] >= 32, flag[i] <= 126)

# Equações extraídas da VM
solver.add((flag[9] * flag[27]) * ((flag[23]-flag[18]) ^ flag[29]) == 0x3fcf)
# ... inserir aqui todas as demais equações encontradas ...

if solver.check() == sat:
    m = solver.model()
    result = "".join(chr(m[flag[i]].as_long()) for i in perm)
    print(result)

```

Rodando o solver com todas as equações extraídas, obtém-se o `Citizen ID` válido:


```
q4Eo-eyMq-1dd0-leKx
```

Esse é o valor que deve ser fornecido ao programa. Ao executá-lo com essa entrada, o binário retorna:

```
[+] ACCESS GRANTED FLAG-l0rdoFb1Nq4EoeyMq1dd0leKx
```

