# Crypto Tool - README

Este projeto é um **script em Python** que demonstra como:
- Gerar um par de chaves RSA (privada e pública),
- Criptografar arquivos usando um **esquema híbrido** (chave simétrica AES-GCM + chave RSA),
- Descriptografar arquivos,
- Realizar exclusão segura (limitada) de arquivos críticos,
- E, se desejado, **autodestruir** o próprio script.

> **Observação**: Este código tem fins **didáticos**. Em ambiente de produção, há diversas considerações extras de segurança e robustez que podem ser necessárias.

---

## Funcionalidades Principais

1. **Geração de Chaves RSA**  
   - Gera um par (privada + pública) e salva em formato PEM.  
   - É possível proteger a chave privada com **passphrase**.

2. **Criptografia de Arquivos (Esquema Híbrido)**  
   - Para criptografar, o script cria uma **chave simétrica AES** e a criptografa com a chave pública RSA.  
   - Em seguida, usa AES-GCM para cifrar o arquivo original em blocos, gerando um arquivo de saída que contém:  
     - Chave simétrica (cifrada com RSA),  
     - Nonce (12 bytes),  
     - Blocos de dados cifrados.

3. **Descriptografia de Arquivos**  
   - Carrega a chave privada RSA (com a passphrase, se tiver).  
   - Extrai e decifra a chave simétrica armazenada no arquivo.  
   - Em seguida, usa essa chave simétrica para decifrar o restante do arquivo em blocos.

4. **Exclusão Segura**  
   - O script provê uma função para sobrescrever um arquivo com zeros antes de excluí-lo, dificultando a recuperação forense.  
   - Em sistemas de arquivos modernos e em SSDs, nem sempre é garantido que isso remova completamente o conteúdo. Ainda assim, é uma mitigação.

5. **Autodestruição**  
   - Apaga os arquivos de chave (`public_key.pem`, `private_key.pem`, `app.log`) e, opcionalmente, o próprio script Python.

---

## Estrutura do Código

O script em **um único arquivo** (`crypto_tool.py`) tem as seguintes partes:

1. **Importações**:  
   - `cryptography`: para operações de RSA, AES-GCM, hashing, serialização de chaves.  
   - `secrets`: para geração de bytes aleatórios de forma segura.  
   - Outras bibliotecas padrão (`os`, `sys`, `datetime`, etc.).

2. **Classe `Logger`**:  
   - Registra eventos em console e em um arquivo `app.log`.  
   - Contém métodos `info`, `error` e `debug`.

3. **Funções Utilitárias**:
   - `secure_delete_file(filepath)`: sobrescreve e remove um arquivo.  
   - `clear_self()`: tenta apagar o próprio script.  
   - `get_secure_random_bytes(size)`: retorna bytes aleatórios.

4. **Classe `CryptoManager`**:
   - Responsável por:
     - **Gerar chaves RSA** (`generate_rsa_keypair`),  
     - **Salvar/carregar chaves** (`save_key_to_file`, `load_private_key`, `load_public_key`),  
     - **Criptografar arquivos** com RSA + AES-GCM (`encrypt_file`),  
     - **Descriptografar arquivos** gerados (`decrypt_file`).

5. **Função `main()`**:
   - Exibe um menu interativo no terminal:
     1. Gera par de chaves RSA.  
     2. Criptografa arquivo.  
     3. Descriptografa arquivo.  
     4. Autodestruição (apaga chaves, log e o próprio script).  
     0. Sai da aplicação.

---

## Requisitos

- **Python 3.6+** (ou superior),
- Biblioteca [**cryptography**](https://pypi.org/project/cryptography/). Para instalar:
  ```bash
  pip install cryptography
  ```
- Permissões de leitura/gravação no diretório onde o script roda (para criar/ler arquivos .pem, logs e arquivos criptografados).

---

## Como Executar

1. **Instale dependências**:
   ```bash
   pip install cryptography
   ```

2. **Execute o script**:
   ```bash
   python crypto_tool.py
   ```
   Será exibido um menu com opções numeradas.

3. **Gere um par de chaves (opção 1)**:
   - Informe tamanho (exemplo: `2048`), e opcionalmente uma passphrase.  
   - As chaves serão salvas como `private_key.pem` e `public_key.pem`.

4. **Criptografe um arquivo (opção 2)**:
   - Informe o caminho do arquivo original (ex: `segredo.txt`), o nome do arquivo criptografado (ex: `encrypted.bin`), e o caminho da chave pública (ex: `public_key.pem`).  
   - O script gerará `encrypted.bin` contendo dados cifrados.

5. **Descriptografe um arquivo (opção 3)**:
   - Indique o arquivo criptografado (`encrypted.bin`), o nome do arquivo de saída decifrado, o caminho da chave privada e a passphrase (se houver).  
   - O script recriará o conteúdo original no arquivo de saída.

6. **Autodestruição (opção 4)**:
   - Remove as chaves (`public_key.pem`, `private_key.pem`), o log (`app.log`) e tenta excluir o próprio script (`crypto_tool.py`).  
   - Use com cautela, pois não terá mais acesso ao código nem às chaves.

7. **Sair (opção 0)**:
   - Encerra o programa.

---

## Observações Importantes

- **AES-GCM com nonce fixo** para cada chunk:  
  - No script, cada bloco do arquivo é cifrado usando o **mesmo nonce**. Em uso real, **não é recomendável**. O ideal é utilizar um nonce distinto para cada bloco ou derivar um nonce incremental para evitar riscos de segurança.  
- **Proteção de Chaves Privadas**:  
  - Se a chave privada não tiver passphrase ou se for guardada sem criptografia adicional, qualquer um com acesso ao arquivo poderá usá-la para descriptografar dados.  
- **Exclusão Segura**:  
  - Mesmo sobrescrevendo o arquivo, sistemas de arquivos modernos e SSDs podem manter dados em blocos de memória diferentes do setor original. Portanto, a exclusão segura pode não ser totalmente eficaz.  
- **Zeroização de Memória**:  
  - Em Python, não há garantia de limpeza imediata de dados sensíveis da memória.  
- **Uso em Produção**:  
  - Teste exaustivamente e considere soluções de hardware seguro (HSM) para armazenar chaves privadas, controle de acesso avançado, logs de auditoria robustos, etc.

---

## Licença

Este exemplo é de uso livre, mas **sem garantias**. Sinta-se à vontade para adaptar, melhorar e redistribuir, conforme suas necessidades. Entretanto, **use por sua conta e risco**, pois não há responsabilidade quanto a eventuais falhas ou prejuízos.
