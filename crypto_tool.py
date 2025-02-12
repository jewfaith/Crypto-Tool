#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import secrets
import datetime

# Instale a biblioteca 'cryptography' caso ainda não tenha:
#    pip install cryptography
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import (
    rsa, padding
)
from cryptography.hazmat.primitives.serialization import (
    PrivateFormat, PublicFormat, Encoding, BestAvailableEncryption,
    load_pem_private_key, load_pem_public_key
)


######################################################################
# 1) Logger simples: grava logs em console e em arquivo app.log
######################################################################
class Logger:
    def __init__(self, logfile="app.log"):
        self.logfile = logfile

    def _write(self, level: str, message: str):
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        formatted = f"[{level}] {timestamp}: {message}"
        # Exibe no console
        print(formatted)
        # Tenta escrever em arquivo de log
        try:
            with open(self.logfile, "a", encoding="utf-8") as f:
                f.write(formatted + "\n")
        except Exception:
            pass  # Evitar travar se não conseguir escrever em log

    def info(self, message: str):
        self._write("INFO", message)

    def error(self, message: str):
        self._write("ERROR", message)

    def debug(self, message: str):
        self._write("DEBUG", message)


######################################################################
# 2) Funções utilitárias seguras (na medida do possível em Python)
######################################################################
def secure_delete_file(filepath: str) -> bool:
    """
    Tenta sobrescrever o conteúdo do arquivo com zeros e depois remover.
    Atenção: em sistemas de arquivos modernos (especialmente SSDs), 
    não é garantido que isso elimine completamente os dados.
    """
    if not os.path.exists(filepath):
        return False
    try:
        length = os.path.getsize(filepath)
        # Sobrescreve com zeros
        with open(filepath, "r+b") as f:
            f.seek(0)
            f.write(b"\x00" * length)
        os.remove(filepath)
        return True
    except Exception:
        return False

def clear_self():
    """
    Autoexclusão do próprio script, se possível.
    """
    try:
        script_path = os.path.abspath(sys.argv[0])
        if os.path.exists(script_path):
            secure_delete_file(script_path)
    except Exception:
        pass

def get_secure_random_bytes(size: int) -> bytes:
    """
    Retorna 'size' bytes aleatórios, usando 'secrets' (CRIPTO-FORTE).
    """
    return secrets.token_bytes(size)


######################################################################
# 3) Classe principal para operações criptográficas
######################################################################
class CryptoManager:
    def __init__(self, logger: Logger):
        self.logger = logger

    def generate_rsa_keypair(self, key_size=2048, passphrase=None):
        """
        Gera um par de chaves RSA (privada e pública).
        Retorna uma tupla (private_bytes, public_bytes).
        Caso 'passphrase' seja fornecida, a chave privada será protegida.
        """
        try:
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=key_size
            )

            # Serialização da chave privada
            if passphrase:
                encryption_alg = BestAvailableEncryption(passphrase.encode())
            else:
                encryption_alg = None

            private_bytes = private_key.private_bytes(
                encoding=Encoding.PEM,
                format=PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=encryption_alg
            )

            # Serialização da chave pública
            public_key = private_key.public_key()
            public_bytes = public_key.public_bytes(
                encoding=Encoding.PEM,
                format=PublicFormat.SubjectPublicKeyInfo
            )

            self.logger.info(f"Chave RSA de {key_size} bits gerada com sucesso.")
            return private_bytes, public_bytes

        except Exception as e:
            self.logger.error(f"Erro ao gerar chave RSA: {e}")
            raise

    def save_key_to_file(self, key_data: bytes, filepath: str):
        """Salva bytes de chave em um arquivo .pem."""
        try:
            with open(filepath, "wb") as f:
                f.write(key_data)
            self.logger.info(f"Chave salva em {filepath}")
        except Exception as e:
            self.logger.error(f"Erro ao salvar chave em {filepath}: {e}")
            raise

    def load_private_key(self, filepath: str, passphrase=None):
        """
        Carrega uma chave privada RSA em PEM (com ou sem passphrase).
        Retorna o objeto de chave privada.
        """
        try:
            with open(filepath, "rb") as f:
                pem_data = f.read()
            private_key = load_pem_private_key(
                pem_data,
                password=(passphrase.encode() if passphrase else None)
            )
            self.logger.info(f"Chave privada carregada: {filepath}")
            return private_key
        except Exception as e:
            self.logger.error(f"Erro ao carregar chave privada: {e}")
            raise

    def load_public_key(self, filepath: str):
        """
        Carrega uma chave pública RSA em PEM.
        Retorna o objeto de chave pública.
        """
        try:
            with open(filepath, "rb") as f:
                pem_data = f.read()
            public_key = load_pem_public_key(pem_data)
            self.logger.info(f"Chave pública carregada: {filepath}")
            return public_key
        except Exception as e:
            self.logger.error(f"Erro ao carregar chave pública: {e}")
            raise

    def encrypt_file(self, infile: str, outfile: str, public_key_path: str):
        """
        Criptografa um arquivo usando esquema híbrido RSA + AESGCM.
        Formato de saída:
          [4 bytes: tamanho da chave RSA-cifrada] [chave_cifrada] [12 bytes de nonce]
          [4 bytes: tamanho do bloco cifrado] [bloco cifrado] ...
        Observação: nesse exemplo, o mesmo nonce é reutilizado em cada bloco GCM,
        o que não é o ideal em produção. Preferir gerar um nonce diferente para cada bloco.
        """
        try:
            public_key = self.load_public_key(public_key_path)

            # 1) Gera chave AES-256 e nonce
            aes_key = get_secure_random_bytes(32)  # 256 bits
            nonce = get_secure_random_bytes(12)

            # 2) Criptografa a chave AES com RSA
            encrypted_key = public_key.encrypt(
                aes_key,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )

            aesgcm = AESGCM(aes_key)
            
            with open(infile, "rb") as fin, open(outfile, "wb") as fout:
                # Escreve a chave simétrica RSA-cifrada + nonce
                fout.write(len(encrypted_key).to_bytes(4, "big"))
                fout.write(encrypted_key)
                fout.write(nonce)

                # Criptografa o arquivo em blocos
                chunk_size = 4096
                while True:
                    chunk = fin.read(chunk_size)
                    if not chunk:
                        break
                    # Criptografa chunk usando AESGCM
                    ciphertext = aesgcm.encrypt(nonce, chunk, None)
                    fout.write(len(ciphertext).to_bytes(4, "big"))
                    fout.write(ciphertext)

            self.logger.info(f"Arquivo '{infile}' criptografado -> '{outfile}'.")
        except Exception as e:
            self.logger.error(f"Erro ao criptografar '{infile}': {e}")
            raise

    def decrypt_file(self, infile: str, outfile: str, private_key_path: str, passphrase=None):
        """
        Descriptografa arquivo criado em 'encrypt_file'.
        Lê a chave simétrica RSA-cifrada, decifra com chave privada RSA,
        então decifra os blocos AESGCM e grava em 'outfile'.
        """
        try:
            private_key = self.load_private_key(private_key_path, passphrase)

            with open(infile, "rb") as fin, open(outfile, "wb") as fout:
                # Tamanho da chave RSA-cifrada
                size_bytes = fin.read(4)
                if len(size_bytes) < 4:
                    raise ValueError("Arquivo inválido ou corrompido (sem metadados suficientes).")
                enc_key_size = int.from_bytes(size_bytes, "big")

                encrypted_key = fin.read(enc_key_size)
                if len(encrypted_key) < enc_key_size:
                    raise ValueError("Arquivo corrompido (chave RSA-cifrada incompleta).")

                # Lê nonce (12 bytes)
                nonce = fin.read(12)
                if len(nonce) < 12:
                    raise ValueError("Arquivo inválido (nonce ausente).")

                # Decifra a chave AES
                aes_key = private_key.decrypt(
                    encrypted_key,
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                    )
                )

                aesgcm = AESGCM(aes_key)

                # Lê e decifra blocos
                while True:
                    block_size_data = fin.read(4)
                    if not block_size_data:
                        # Fim do arquivo
                        break

                    block_size = int.from_bytes(block_size_data, "big")
                    if block_size <= 0:
                        break

                    ciphertext = fin.read(block_size)
                    if len(ciphertext) < block_size:
                        raise ValueError("Arquivo corrompido (bloco cifrado incompleto).")

                    plaintext = aesgcm.decrypt(nonce, ciphertext, None)
                    fout.write(plaintext)

            self.logger.info(f"Arquivo '{infile}' decifrado -> '{outfile}'.")
        except Exception as e:
            self.logger.error(f"Erro ao descriptografar '{infile}': {e}")
            raise


######################################################################
# 4) Função principal (menu simples de linha de comando)
######################################################################
def print_menu():
    print("\n=== Crypto Tool ===")
    print("1. Gerar par de chaves RSA")
    print("2. Criptografar arquivo")
    print("3. Descriptografar arquivo")
    print("4. Autodestruir script e chaves")
    print("0. Sair")

def main():
    logger = Logger()
    cm = CryptoManager(logger)

    while True:
        print_menu()
        choice = input("Escolha uma opção: ")

        if choice == "1":
            print("\n--- Gerar Par de Chaves RSA ---")
            key_size_str = input("Tamanho da chave (ex: 2048, 3072): ")
            passphrase = input("Passphrase (opcional, Enter se não quiser): ")

            try:
                key_size = int(key_size_str)
            except ValueError:
                logger.error("Tamanho inválido, usando 2048.")
                key_size = 2048

            try:
                priv_bytes, pub_bytes = cm.generate_rsa_keypair(key_size=key_size,
                                                               passphrase=passphrase if passphrase else None)
                cm.save_key_to_file(pub_bytes, "public_key.pem")
                cm.save_key_to_file(priv_bytes, "private_key.pem")
                input("[INFO] Chaves geradas. Pressione Enter para continuar...")
            except Exception as e:
                print(f"[ERRO] Falha ao gerar par de chaves: {e}")
                input("[INFO] Retornando ao menu...")

        elif choice == "2":
            print("\n--- Criptografar Arquivo ---")
            infile = input("Arquivo de entrada: ")
            outfile = input("Arquivo de saída (ex: encrypted.bin): ")
            pubkey_path = input("Caminho da chave pública (ex: public_key.pem): ")

            if not os.path.exists(infile):
                print("[ERRO] Arquivo de entrada não existe.")
                continue
            if not os.path.exists(pubkey_path):
                print("[ERRO] Chave pública inexistente.")
                continue

            try:
                cm.encrypt_file(infile, outfile, pubkey_path)
                input("[INFO] Concluído. Pressione Enter para continuar...")
            except Exception as e:
                print(f"[ERRO] Criptografia falhou: {e}")
                input("[INFO] Retornando ao menu...")

        elif choice == "3":
            print("\n--- Descriptografar Arquivo ---")
            infile = input("Arquivo criptografado: ")
            outfile = input("Arquivo de saída (ex: decifrado.txt): ")
            privkey_path = input("Caminho da chave privada (ex: private_key.pem): ")
            passphrase = input("Passphrase (se houver): ")

            if not os.path.exists(infile):
                print("[ERRO] Arquivo de entrada não existe.")
                continue
            if not os.path.exists(privkey_path):
                print("[ERRO] Chave privada inexistente.")
                continue

            try:
                cm.decrypt_file(infile, outfile, privkey_path, passphrase if passphrase else None)
                input("[INFO] Concluído. Pressione Enter para continuar...")
            except Exception as e:
                print(f"[ERRO] Descriptografia falhou: {e}")
                input("[INFO] Retornando ao menu...")

        elif choice == "4":
            print("\n--- Autodestruir ---")
            # Apagar chaves
            for f in ["public_key.pem", "private_key.pem", "app.log"]:
                if os.path.exists(f):
                    if secure_delete_file(f):
                        print(f"[INFO] Arquivo '{f}' removido com segurança.")
                    else:
                        print(f"[AVISO] Não foi possível remover '{f}' com segurança.")
            # Remover o próprio script
            clear_self()
            print("[INFO] Tentando remover o próprio script. Encerrando...")
            os._exit(0)

        elif choice == "0":
            print("Saindo...")
            break

        else:
            print("[ERRO] Opção inválida. Tente novamente.")


if __name__ == "__main__":
    main()
