"""
Cifra própria (didática) do Projeto 1: SPN de 64 bits, chave dinâmica.

Decisões do projeto:
  - Estrutura SPN (substituição + permutação), como o AES
  - Bloco de 64 bits (8 bytes)
  - Rodadas parametrizáveis (padrão 6)
  - Chave mestra de 32, 64 ou 128 bits, derivada por senha + salt aleatório (PBKDF2)
  - Subchaves: K_r = SHA-256(chave_mestra || r)[:8]
  - S-box fixa de 8 bits, gerada uma vez e validada (bijetiva, sem pontos fixos)
  - Camada P: transposição da matriz 8x8 de bits (cada bit de saída de uma
    S-box vai para uma S-box diferente na rodada seguinte)
  - Modos: ECB (só para demonstrar vazamento) e CBC (modo oficial)
  - Integridade: HMAC-SHA256 sobre salt|IV|cifrado (encrypt-then-MAC)

Rodada r (1..N):  estado ^= K_r -> S-box em cada byte -> camada P
Final:            estado ^= K_(N+1)
"""
import hashlib
import os
import random

BLOCK = 8                    # bytes (64 bits)
DEFAULT_ROUNDS = 6
KEY_SIZES = (32, 64, 128)    # bits
PBKDF2_ITERS = 100_000
SALT_LEN = 16


# ---------- S-box ----------
def _gerar_sbox(seed: int = 2026):
    rng = random.Random(seed)
    while True:
        s = list(range(256))
        rng.shuffle(s)
        if all(s[i] != i for i in range(256)):          # sem pontos fixos
            return s

SBOX = _gerar_sbox()
INV_SBOX = [0] * 256
for _i, _v in enumerate(SBOX):
    INV_SBOX[_v] = _i
assert sorted(SBOX) == list(range(256)), "S-box precisa ser bijetiva"


# ---------- Camada P (transposição 8x8 de bits) ----------
def _pos_destino(i: int) -> int:
    """bit i (byte i//8, bit i%8) -> byte i%8, bit i//8. É uma involução."""
    return (i % 8) * 8 + i // 8

# tabela: para cada byte j e valor v, a contribuição em 64 bits após a permutação
_PTAB = [[0] * 256 for _ in range(8)]
for _j in range(8):
    for _v in range(256):
        out = 0
        for _b in range(8):
            if (_v >> _b) & 1:
                out |= 1 << _pos_destino(_j * 8 + _b)
        _PTAB[_j][_v] = out

def _p_layer(x: int) -> int:
    out = 0
    for j in range(8):
        out |= _PTAB[j][(x >> (8 * j)) & 0xFF]
    return out
# transposição é sua própria inversa
_inv_p_layer = _p_layer


def _s_layer(x: int, box) -> int:
    out = 0
    for j in range(8):
        out |= box[(x >> (8 * j)) & 0xFF] << (8 * j)
    return out


# ---------- Chaves ----------
def derivar_chave(senha: str, salt: bytes, key_bits: int = 128,
                  iters: int = PBKDF2_ITERS) -> bytes:
    if key_bits not in KEY_SIZES:
        raise ValueError(f"key_bits deve ser um de {KEY_SIZES}")
    return hashlib.pbkdf2_hmac("sha256", senha.encode(), salt, iters,
                               dklen=key_bits // 8)

def subchaves(chave: bytes, rounds: int = DEFAULT_ROUNDS):
    return [int.from_bytes(hashlib.sha256(chave + bytes([r])).digest()[:8], "little")
            for r in range(rounds + 1)]


# ---------- Bloco ----------
def cifrar_bloco(x: int, ks, rounds: int) -> int:
    for r in range(rounds):
        x ^= ks[r]
        x = _s_layer(x, SBOX)
        x = _p_layer(x)
    return x ^ ks[rounds]

def decifrar_bloco(x: int, ks, rounds: int) -> int:
    x ^= ks[rounds]
    for r in reversed(range(rounds)):
        x = _inv_p_layer(x)
        x = _s_layer(x, INV_SBOX)
        x ^= ks[r]
    return x


# ---------- Padding PKCS#7 ----------
def _pad(d: bytes) -> bytes:
    n = BLOCK - len(d) % BLOCK
    return d + bytes([n]) * n

def _unpad(d: bytes) -> bytes:
    n = d[-1]
    if not 1 <= n <= BLOCK or d[-n:] != bytes([n]) * n:
        raise ValueError("padding inválido (falha de decifração)")
    return d[:-n]


# ---------- Modos ----------
def cifrar_bytes(dados: bytes, chave: bytes, modo: str = "CBC",
                 rounds: int = DEFAULT_ROUNDS, iv: bytes | None = None,
                 padding: bool = True) -> bytes:
    ks = subchaves(chave, rounds)
    p = _pad(dados) if padding else dados
    out = bytearray()
    if modo == "ECB":
        for i in range(0, len(p), BLOCK):
            b = int.from_bytes(p[i:i + BLOCK], "little")
            out += cifrar_bloco(b, ks, rounds).to_bytes(BLOCK, "little")
        return bytes(out)
    if modo == "CBC":
        iv = iv or os.urandom(BLOCK)
        prev = int.from_bytes(iv, "little")
        for i in range(0, len(p), BLOCK):
            b = int.from_bytes(p[i:i + BLOCK], "little") ^ prev
            prev = cifrar_bloco(b, ks, rounds)
            out += prev.to_bytes(BLOCK, "little")
        return iv + bytes(out)
    raise ValueError("modo deve ser ECB ou CBC")

def decifrar_bytes(dados: bytes, chave: bytes, modo: str = "CBC",
                   rounds: int = DEFAULT_ROUNDS, padding: bool = True) -> bytes:
    ks = subchaves(chave, rounds)
    out = bytearray()
    if modo == "ECB":
        for i in range(0, len(dados), BLOCK):
            b = int.from_bytes(dados[i:i + BLOCK], "little")
            out += decifrar_bloco(b, ks, rounds).to_bytes(BLOCK, "little")
    elif modo == "CBC":
        prev = int.from_bytes(dados[:BLOCK], "little")
        for i in range(BLOCK, len(dados), BLOCK):
            c = int.from_bytes(dados[i:i + BLOCK], "little")
            out += (decifrar_bloco(c, ks, rounds) ^ prev).to_bytes(BLOCK, "little")
            prev = c
    else:
        raise ValueError("modo deve ser ECB ou CBC")
    return _unpad(bytes(out)) if padding else bytes(out)


# ---------- API de mensagem (senha -> pacote autenticado) ----------
import hmac

TAG_LEN = 32

class IntegridadeError(ValueError):
    """Tag HMAC não confere: senha errada ou pacote adulterado."""

def _chaves_enc_mac(senha: str, salt: bytes, key_bits: int):
    """Uma derivação PBKDF2 gera a chave de cifra (key_bits) + 32 bytes de chave HMAC."""
    bruto = hashlib.pbkdf2_hmac("sha256", senha.encode(), salt, PBKDF2_ITERS,
                                dklen=key_bits // 8 + 32)
    return bruto[:key_bits // 8], bruto[key_bits // 8:]

def cifrar_mensagem(texto: str, senha: str, key_bits: int = 128,
                    rounds: int = DEFAULT_ROUNDS) -> bytes:
    """Pacote = salt(16) | IV(8) | cifrado | tag HMAC-SHA256(32)  (encrypt-then-MAC).
    Salt novo a cada mensagem => chave nunca fixa."""
    if key_bits not in KEY_SIZES:
        raise ValueError(f"key_bits deve ser um de {KEY_SIZES}")
    salt = os.urandom(SALT_LEN)
    k_enc, k_mac = _chaves_enc_mac(senha, salt, key_bits)
    corpo = salt + cifrar_bytes(texto.encode("utf-8"), k_enc, "CBC", rounds)
    return corpo + hmac.new(k_mac, corpo, hashlib.sha256).digest()

def decifrar_mensagem(pacote: bytes, senha: str, key_bits: int = 128,
                      rounds: int = DEFAULT_ROUNDS) -> str:
    corpo, tag = pacote[:-TAG_LEN], pacote[-TAG_LEN:]
    salt = corpo[:SALT_LEN]
    k_enc, k_mac = _chaves_enc_mac(senha, salt, key_bits)
    if not hmac.compare_digest(tag, hmac.new(k_mac, corpo, hashlib.sha256).digest()):
        raise IntegridadeError("falha de integridade: senha errada ou mensagem adulterada")
    return decifrar_bytes(corpo[SALT_LEN:], k_enc, "CBC", rounds).decode("utf-8")
