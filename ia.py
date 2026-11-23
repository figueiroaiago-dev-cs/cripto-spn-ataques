"""
Etapa 6 — IA: detecção de anomalias com Isolation Forest (não supervisionado)
comparada a regras simples de base. Rótulos injetados são usados SÓ na avaliação.

Visões:  IP x hora      -> força bruta, credential stuffing
         usuário x hora -> acesso atípico/exfiltração, alteração de arquivo
Saídas:  dados/janelas.parquet (score + alertas p/ dashboard) e resultados/ia.json
Uso:     python ia.py
"""
import json
from pathlib import Path

import duckdb
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.metrics import average_precision_score, confusion_matrix, precision_recall_fscore_support

BASE = Path(__file__).parent
PQ = (BASE / "dados" / "eventos.parquet").as_posix()
OUT = BASE / "resultados"
# orçamento de alertas (contaminação) por visão, escolhido na Etapa 6 pela varredura de orçamento
ORCAMENTO = {"ip_x_hora": 0.002, "usuario_x_hora": 0.005}

ROTULO = """coalesce(max(CASE WHEN rotulo_ataque <> 'normal' THEN rotulo_ataque END), 'normal')"""

SQL_IP = f"""
SELECT ip, date_trunc('hour', ts) AS janela, any_value(pais) AS pais,
       count(*)                                         AS n_eventos,
       count(*) FILTER (WHERE evento = 'login_falha')   AS falhas_login,
       count(*) FILTER (WHERE evento = 'login_ok')      AS logins_ok,
       count(DISTINCT usuario)                          AS usuarios_distintos,
       max(CASE WHEN pais <> 'BR' THEN 1 ELSE 0 END)    AS estrangeiro,
       hour(min(ts))                                    AS hora,
       {ROTULO} AS rotulo
FROM '{PQ}' GROUP BY ip, janela"""

SQL_USR = f"""
SELECT usuario, date_trunc('hour', ts) AS janela,
       count(*)                                                        AS n_eventos,
       count(*) FILTER (WHERE evento IN ('msg_decifrar_ok','stego_extrair')) AS leituras,
       count(*) FILTER (WHERE evento = 'arquivo_hash_divergente')      AS hash_divergente,
       count(*) FILTER (WHERE evento = 'arquivo_escrita')              AS escritas,
       count(*) FILTER (WHERE evento = 'msg_decifrar_falha')           AS falhas_decifrar,
       count(DISTINCT ip)                                              AS ips_distintos,
       max(CASE WHEN pais <> 'BR' THEN 1 ELSE 0 END)                   AS estrangeiro,
       sum(bytes) / 1e6                                                AS mb,
       hour(min(ts))                                                   AS hora,
       CASE WHEN dayofweek(min(ts)) IN (0, 6) THEN 1 ELSE 0 END        AS fim_de_semana,
       {ROTULO} AS rotulo
FROM '{PQ}' GROUP BY usuario, janela"""

def _hora_ciclica(df):
    df["hora_sin"] = np.sin(2 * np.pi * df["hora"] / 24); df["hora_cos"] = np.cos(2 * np.pi * df["hora"] / 24)
    return df

def treinar(df, features, regra, orcamento):
    X = df[features].astype(float).copy()
    for c in features:
        if not c.startswith("hora_") and c not in ("estrangeiro", "fim_de_semana"):
            X[c] = np.log1p(X[c])
    modelo = IsolationForest(n_estimators=300, contamination=orcamento, random_state=42)
    modelo.fit(X)                                         # sem rótulos
    df["score"] = -modelo.score_samples(X)                # maior = mais anômalo
    df["alerta_ia"] = modelo.predict(X) == -1
    df["alerta_regra"] = regra(df)
    df["alerta"] = df["alerta_ia"] | df["alerta_regra"]
    return df

ESCOPO = {"ip_x_hora": {"forca_bruta", "acesso_atipico"},          # ataques vindos de IP externo
          "usuario_x_hora": {"forca_bruta", "acesso_atipico", "alteracao_arquivo"}}

def avaliar(df, visao):
    # janelas de ataques fora do escopo da visão saem da avaliação (ex.: alteração de arquivo
    # vem do IP legítimo do usuário, então a visão por IP não tem como enxergá-la)
    fora = (df["rotulo"] != "normal") & ~df["rotulo"].isin(ESCOPO[visao])
    df = df[~fora]
    y = df["rotulo"] != "normal"; r = {"fora_do_escopo": int(fora.sum()),
                                       "average_precision_ia": round(float(average_precision_score(y, df["score"])), 3)}
    varre = []
    for orc in (0.002, 0.005, 0.01, 0.02):
        k = max(1, int(round(orc * len(df)))); top = df["score"].rank(ascending=False, method="first") <= k
        varre.append({"orcamento": orc, "alertas": k, "vp": int((top & y).sum()), "fp": int((top & ~y).sum()),
                      "recall": round(float((top & y).sum() / y.sum()), 3), "precisao": round(float((top & y).sum() / k), 3)})
    r["varredura_orcamento"] = varre
    for col in ("alerta_regra", "alerta_ia", "alerta"):
        p, rc, f, _ = precision_recall_fscore_support(y, df[col], average="binary", zero_division=0)
        tn, fp, fn, tp = confusion_matrix(y, df[col], labels=[False, True]).ravel()
        r[col] = {"precisao": round(float(p), 3), "recall": round(float(rc), 3), "f1": round(float(f), 3),
                  "vp": int(tp), "fp": int(fp), "fn": int(fn), "vn": int(tn)}
    por_tipo = {}
    for t, g in df[y].groupby("rotulo"):
        por_tipo[t] = {"janelas": len(g), **{c: int(g[c].sum()) for c in ("alerta_regra", "alerta_ia", "alerta")}}
    r["por_tipo"] = por_tipo
    return r

def main():
    con = duckdb.connect()
    ip = _hora_ciclica(con.sql(SQL_IP).df()); us = _hora_ciclica(con.sql(SQL_USR).df())
    ip = treinar(ip, ["n_eventos", "falhas_login", "logins_ok", "usuarios_distintos", "estrangeiro", "hora_sin", "hora_cos"],
                 lambda d: (d["falhas_login"] >= 20) | (d["usuarios_distintos"] >= 5), ORCAMENTO["ip_x_hora"])
    us = treinar(us, ["n_eventos", "leituras", "hash_divergente", "escritas", "falhas_decifrar", "ips_distintos",
                      "estrangeiro", "mb", "fim_de_semana", "hora_sin", "hora_cos"],
                 lambda d: (d["hash_divergente"] >= 1) | (d["leituras"] >= 100), ORCAMENTO["usuario_x_hora"])
    res = {"orcamento_alertas": ORCAMENTO,
           "ip_x_hora": {"janelas": len(ip), **avaliar(ip, "ip_x_hora")},
           "usuario_x_hora": {"janelas": len(us), **avaliar(us, "usuario_x_hora")}}
    ip["visao"] = "ip_x_hora"; us["visao"] = "usuario_x_hora"
    pd.concat([ip, us], ignore_index=True).to_parquet(BASE / "dados" / "janelas.parquet", index=False)
    (OUT / "ia.json").write_text(json.dumps(res, indent=2, ensure_ascii=False), encoding="utf-8")
    for v in ("ip_x_hora", "usuario_x_hora"):
        print(f"\n== {v} ({res[v]['janelas']:,} janelas)")
        for c in ("alerta_regra", "alerta_ia", "alerta"):
            m = res[v][c]; print(f"  {c:13s} P={m['precisao']:.2f} R={m['recall']:.2f} F1={m['f1']:.2f}  VP={m['vp']} FP={m['fp']} FN={m['fn']}")
        for t, d in res[v]["por_tipo"].items(): print(f"  {t:18s} {d}")
        print(f"  AP(IA)={res[v]['average_precision_ia']}  fora do escopo={res[v]['fora_do_escopo']}")
        for o in res[v]["varredura_orcamento"]: print("   ", o)
    print("\nTop 5 janelas mais anômalas (usuário x hora):")
    print(us.nlargest(5, "score")[["usuario", "janela", "n_eventos", "leituras", "estrangeiro", "hora", "score", "rotulo"]].to_string(index=False))

if __name__ == "__main__":
    main()
