"""Gerador de mensagens sintéticas de chat em pt-BR (determinístico)."""
import random

USUARIOS = ["ana", "bruno", "carla", "diego", "elisa", "felipe", "gabi", "hugo",
            "iago", "julia", "lucas", "marina", "nina", "otavio", "paula", "rafa"]
TEMPLATES = [
    "Oi {u}, tudo bem? Vamos marcar a reunião para {d} às {h}h?",
    "Bom dia! O relatório de {p} já foi enviado para {u}.",
    "{u}, consegue revisar o documento até {d}?",
    "Confirmado: entrega do lote {n} na {d}.",
    "Pessoal, a senha do wifi mudou. Falem com {u}.",
    "Ok, combinado. Te ligo às {h}h.",
    "Segue o código de acesso: {n}. Não compartilhe.",
    "Valeu {u}! Até amanhã.",
    "Alguém viu o e-mail sobre {p}?",
    "Atenção: manutenção no servidor {n} {d} às {h}h.",
    "Pagamento de R$ {n},00 aprovado pelo financeiro.",
    "Kkkk verdade. Depois a gente vê isso.",
]
DIAS = ["segunda", "terça", "quarta", "quinta", "sexta", "sábado"]
PROJ = ["vendas", "PCP", "estoque", "compras", "auditoria", "segurança"]

def gerar(n=2000, seed=42):
    rng = random.Random(seed)
    msgs = []
    for _ in range(n):
        t = rng.choice(TEMPLATES)
        msgs.append(t.format(u=rng.choice(USUARIOS).capitalize(), d=rng.choice(DIAS),
                             h=rng.randint(8, 18), p=rng.choice(PROJ),
                             n=rng.randint(100, 9999)))
    return msgs

if __name__ == "__main__":
    for m in gerar(5): print(m)
