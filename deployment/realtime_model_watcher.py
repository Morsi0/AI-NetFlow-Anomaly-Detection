import os
import time
import glob
import json
import numpy as np
import pandas as pd
import torch
import torch.nn as nn
import joblib
from datetime import datetime, timezone

# =========================================================
# ARCHITECTURE (identique au training)
# =========================================================
class NetflowTransformer(nn.Module):
    def __init__(
        self, input_dim, num_classes,
        model_dim=64, num_heads=4,
        num_layers=2, seq_len=10, dropout=0.3
    ):
        super().__init__()
        self.input_projection = nn.Linear(input_dim, model_dim)
        self.pos_embedding = nn.Parameter(
            torch.randn(1, seq_len, model_dim) * 0.02
        )
        self.input_norm = nn.LayerNorm(model_dim)
        encoder_layer = nn.TransformerEncoderLayer(
            d_model=model_dim, nhead=num_heads,
            dim_feedforward=model_dim * 4, dropout=dropout,
            batch_first=True, norm_first=True
        )
        self.transformer_encoder = nn.TransformerEncoder(encoder_layer, num_layers=num_layers)
        self.post_norm = nn.LayerNorm(model_dim)
        self.pool = nn.Linear(model_dim, 1)
        self.classifier = nn.Sequential(
            nn.Linear(model_dim, model_dim // 2),
            nn.GELU(),
            nn.Dropout(dropout),
            nn.Linear(model_dim // 2, num_classes)
        )

    def forward(self, x):
        x = self.input_projection(x)
        x = x + self.pos_embedding[:, :x.size(1), :]
        x = self.input_norm(x)
        x = self.transformer_encoder(x)
        x = self.post_norm(x)
        attn = torch.softmax(self.pool(x), dim=1)
        x = torch.sum(x * attn, dim=1)
        return self.classifier(x)


# =========================================================
# PATHS  ← À adapter
# =========================================================
CSV_DIR          = "/home/victim/captures_nids/csv_ia"
MODEL_PATH       = "/home/victim/Downloads/model.pth"
SCALER_PATH      = "/home/victim/Downloads/scaler.pkl"
META_PATH        = "/home/victim/Downloads/model_meta.json"
OUTPUT_PATH      = "/home/victim/captures_nids/realtime_predictions.csv"
WAZUH_ALERT_PATH = "/home/victim/captures_nids/nids_alerts.json"

WINDOW               = 10
CONFIDENCE_THRESHOLD = 0.70
MAX_BUFFER           = 5000

LABELS_COLS = [
    "Benign", "Exfiltration", "Brute_SSH",
    "Port_Scan", "Slowloris", "Vul_Scan",
]

FEATURE_COLS_RAW = [
    'dst_port', 'protocol', 'flow_duration',
    'flow_byts_s', 'flow_pkts_s',
    'tot_fwd_pkts', 'tot_bwd_pkts', 'totlen_fwd_pkts',
    'fwd_pkt_len_max', 'fwd_pkt_len_min', 'fwd_pkt_len_mean',
    'bwd_pkt_len_max', 'bwd_pkt_len_min', 'bwd_pkt_len_mean', 'bwd_pkt_len_std',
    'pkt_len_max', 'pkt_len_min', 'pkt_len_mean', 'pkt_len_var',
    'fwd_seg_size_min', 'fwd_act_data_pkts',
    'flow_iat_mean', 'flow_iat_max', 'flow_iat_min', 'flow_iat_std',
    'fwd_iat_mean', 'fwd_iat_std',
    'bwd_iat_tot', 'bwd_iat_max', 'bwd_iat_mean', 'bwd_iat_std',
    'fwd_psh_flags', 'bwd_psh_flags', 'fwd_urg_flags', 'bwd_urg_flags',
    'fin_flag_cnt', 'rst_flag_cnt', 'psh_flag_cnt',
    'ack_flag_cnt', 'urg_flag_cnt', 'cwr_flag_count',
    'down_up_ratio',
    'init_fwd_win_byts', 'init_bwd_win_byts',
    'active_min', 'active_mean', 'active_std',
    'idle_mean', 'idle_std',
    'fwd_byts_b_avg', 'fwd_pkts_b_avg', 'bwd_byts_b_avg', 'bwd_pkts_b_avg',
    'fwd_blk_rate_avg', 'bwd_blk_rate_avg',
]

DROP_STATIC = [
    'fwd_pkts_s', 'bwd_pkts_s', 'fwd_iat_tot', 'fwd_iat_max', 'fwd_iat_min',
    'bwd_iat_min', 'fwd_header_len', 'bwd_header_len', 'fwd_pkt_len_std',
    'pkt_len_std', 'syn_flag_cnt', 'ece_flag_cnt', 'pkt_size_avg',
    'fwd_seg_size_avg', 'bwd_seg_size_avg', 'subflow_fwd_pkts', 'subflow_bwd_pkts',
    'subflow_fwd_byts', 'subflow_bwd_byts', 'active_max', 'idle_max', 'idle_min',
    'totlen_bwd_pkts', 'src_port',
]

COMMON_PORTS = {80, 443, 53, 21, 22, 25, 110, 143, 3306, 5432}

def port_bin(port):
    if port in COMMON_PORTS: return 0
    elif port < 1024:         return 1
    elif port < 49152:        return 2
    else:                     return 3


# =========================================================
# EXTRACTION INFOS RÉSEAU
# =========================================================
NETWORK_COLS_MAP = {
    "src_ip"       : ["src_ip", "source_ip", "src ip", "source ip"],
    "dst_ip"       : ["dst_ip", "destination_ip", "dst ip", "destination ip"],
    "src_port"     : ["src_port", "source_port", "src port"],
    "dst_port"     : ["dst_port", "destination_port", "dst port"],
    "protocol"     : ["protocol"],
    "flow_duration": ["flow_duration", "flow duration"],
    "tot_fwd_pkts" : ["tot_fwd_pkts", "total fwd packets"],
    "tot_bwd_pkts" : ["tot_bwd_pkts", "total backward packets"],
    "flow_byts_s"  : ["flow_byts_s", "flow bytes/s"],
    "flow_pkts_s"  : ["flow_pkts_s", "flow packets/s"],
    "timestamp"    : ["timestamp", "flow_start", "flow start"],
}

def extract_network_info(window_df: pd.DataFrame) -> dict:
    normalized = {
        col.strip().lower().replace(' ', '_').replace('/', '_'): col
        for col in window_df.columns
    }
    info = {}
    for field, candidates in NETWORK_COLS_MAP.items():
        found_col = None
        for candidate in candidates:
            norm_candidate = candidate.strip().lower().replace(' ', '_').replace('/', '_')
            if norm_candidate in normalized:
                found_col = normalized[norm_candidate]
                break
        if found_col is None:
            info[field] = None
            continue
        series = window_df[found_col].dropna()
        if series.empty:
            info[field] = None
            continue
        if field in ("src_ip", "dst_ip", "src_port", "dst_port", "protocol"):
            # Prendre le PREMIER flow — le mode causait src_ip == dst_ip
            info[field] = series.iloc[0]
            if hasattr(info[field], 'item'):
                info[field] = info[field].item()
        elif field == "timestamp":
            info[field] = str(series.iloc[0])
        else:
            try:
                info[field] = round(float(pd.to_numeric(series, errors='coerce').mean()), 4)
            except Exception:
                info[field] = None
    return info


# =========================================================
# ÉCRITURE ALERTE WAZUH
# =========================================================
def write_wazuh_alert(pred_label: str, confidence: float,
                      network_info: dict, source_csv: str):
    event = {
        # ── Métadonnées
        "timestamp"    : datetime.now(timezone.utc).isoformat(),
        "nids_source"  : "transformer_model",
        # ── Résultat IA
        "attack_type"  : pred_label,
        "confidence"   : round(float(confidence), 4),
        "model"        : "NetflowTransformer",
        "window_size"  : int(WINDOW),
        "source_file"  : source_csv,
        # ── Infos réseau — types stricts
        "src_ip"       : str(network_info.get("src_ip") or ""),
        "dst_ip"       : str(network_info.get("dst_ip") or ""),
        "src_port"     : int(network_info.get("src_port") or 0),
        "dst_port"     : int(network_info.get("dst_port") or 0),
        "protocol"     : int(network_info.get("protocol") or 0),
        "flow_duration": round(float(network_info.get("flow_duration") or 0.0), 4),
        "flow_byts_s"  : round(float(network_info.get("flow_byts_s") or 0.0), 4),
        "flow_pkts_s"  : round(float(network_info.get("flow_pkts_s") or 0.0), 4),
        "tot_fwd_pkts" : int(round(float(network_info.get("tot_fwd_pkts") or 0))),  # ← int, plus de float
        "tot_bwd_pkts" : int(round(float(network_info.get("tot_bwd_pkts") or 0))),  # ← int, plus de float
        "flow_start"   : str(network_info.get("timestamp") or ""),
    }

    try:
        with open(WAZUH_ALERT_PATH, "a") as f:
            f.write(json.dumps(event) + "\n")
        print(f"🚨 Alerte Wazuh écrite : {pred_label} (confidence={confidence:.4f})")
    except Exception as e:
        print(f"❌ Erreur écriture alerte Wazuh : {e}")


# =========================================================
# WAIT FILE READY
# =========================================================
def wait_until_file_ready(file_path, wait_seconds=2, max_wait=60):
    waited    = 0
    last_size = -1
    while waited < max_wait:
        if not os.path.exists(file_path):
            time.sleep(wait_seconds)
            waited += wait_seconds
            continue
        current_size = os.path.getsize(file_path)
        if current_size > 0 and current_size == last_size:
            return True
        last_size = current_size
        time.sleep(wait_seconds)
        waited += wait_seconds
    return False


# =========================================================
# PREPARE FEATURES
# =========================================================
def prepare_features(df_raw, feature_cols):
    df = df_raw.copy()
    df.columns = (
        df.columns.str.strip().str.lower()
        .str.replace(' ', '_').str.replace('/', '_')
    )
    df.replace([np.inf, -np.inf], np.nan, inplace=True)
    df.fillna(0, inplace=True)

    for col in FEATURE_COLS_RAW:
        if col not in df.columns:
            df[col] = 0

    if 'protocol' in df.columns:
        proto = pd.to_numeric(df['protocol'], errors='coerce').fillna(0).astype(int)
    else:
        proto = pd.Series(np.zeros(len(df), dtype=int), index=df.index)

    df['proto_0']  = (proto == 0).astype(np.int8)
    df['proto_6']  = (proto == 6).astype(np.int8)
    df['proto_17'] = (proto == 17).astype(np.int8)

    if 'dst_port' in df.columns:
        ports = pd.to_numeric(df['dst_port'], errors='coerce').fillna(0).astype(int)
    else:
        ports = pd.Series(np.zeros(len(df), dtype=int), index=df.index)

    bins = ports.apply(port_bin)
    df['port_0'] = (bins == 0).astype(np.int8)
    df['port_1'] = (bins == 1).astype(np.int8)
    df['port_2'] = (bins == 2).astype(np.int8)
    df['port_3'] = (bins == 3).astype(np.int8)

    result = pd.DataFrame(index=df.index)
    for col in feature_cols:
        if col in df.columns:
            result[col] = pd.to_numeric(df[col], errors='coerce').fillna(0)
        else:
            result[col] = 0.0

    return result.astype(np.float32)


# =========================================================
# LOAD META
# =========================================================
print("📋 Chargement meta modèle...")
if os.path.exists(META_PATH):
    with open(META_PATH) as f:
        meta = json.load(f)
    feature_cols = meta['features']
    if meta.get('labels'):
        LABELS_COLS = meta['labels']
    input_dim = meta['input_dim']
    print(f"✅ Meta chargée — {len(feature_cols)} features, {len(LABELS_COLS)} classes")
else:
    print("⚠️  model_meta.json introuvable — utilisation des valeurs par défaut")
    base = [c for c in FEATURE_COLS_RAW if c not in DROP_STATIC]
    feature_cols = base + ['proto_0', 'proto_6', 'proto_17', 'port_0', 'port_1', 'port_2', 'port_3']
    input_dim = len(feature_cols)

# =========================================================
# LOAD MODEL
# =========================================================
device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
print(f"🚀 Device : {device}")

print("🧠 Chargement modèle...")
model = NetflowTransformer(
    input_dim=input_dim, num_classes=len(LABELS_COLS), seq_len=WINDOW
)
model.load_state_dict(torch.load(MODEL_PATH, map_location=device))
model.to(device)
model.eval()
print("✅ Modèle chargé")

# =========================================================
# LOAD SCALER
# =========================================================
print("📏 Chargement scaler...")
scaler = joblib.load(SCALER_PATH)
print("✅ Scaler chargé")

# =========================================================
# WATCHER
# =========================================================
print(f"\n🚀 IA NIDS Watcher lancé")
print(f"📂 Dossier surveillé : {CSV_DIR}")
print(f"🧠 Window size       : {WINDOW}")
print(f"🎯 Confidence seuil  : {CONFIDENCE_THRESHOLD}")
print(f"📊 Classes           : {LABELS_COLS}")
print(f"🔔 Alertes Wazuh     : {WAZUH_ALERT_PATH}\n")

seen_files         = set(glob.glob(os.path.join(CSV_DIR, "*.csv")))
buffer_df          = pd.DataFrame()
prediction_results = []

# =========================================================
# LOOP PRINCIPALE
# =========================================================
while True:

    csv_files = sorted(glob.glob(os.path.join(CSV_DIR, "*.csv")))

    for file_path in csv_files:

        if file_path in seen_files:
            continue

        print("\n" + "=" * 50)
        print(f"🆕 Nouveau CSV : {os.path.basename(file_path)}")

        print("⏳ Attente écriture complète...")
        if not wait_until_file_ready(file_path):
            print("⚠️  CSV non prêt — ignoré")
            continue

        try:
            df_new = pd.read_csv(file_path)
        except pd.errors.EmptyDataError:
            print("⚠️  CSV vide")
            seen_files.add(file_path)
            continue
        except Exception as e:
            print(f"❌ Erreur lecture : {e}")
            continue

        seen_files.add(file_path)

        if df_new.empty:
            print("⚠️  CSV sans lignes")
            continue

        print(f"📄 Lignes reçues : {len(df_new)}")

        buffer_df = pd.concat([buffer_df, df_new], ignore_index=True)

        if len(buffer_df) > MAX_BUFFER:
            buffer_df = buffer_df.iloc[-MAX_BUFFER:]

        print(f"📦 Buffer actuel : {len(buffer_df)} flows")

        while len(buffer_df) >= WINDOW:

            current_window = buffer_df.iloc[:WINDOW].copy()

            try:
                X_df     = prepare_features(current_window, feature_cols)
                X_scaled = scaler.transform(X_df.values)
                X_tensor = torch.tensor(
                    X_scaled.reshape(1, WINDOW, len(feature_cols)),
                    dtype=torch.float32
                ).to(device)

                with torch.no_grad():
                    outputs             = model(X_tensor)
                    probs               = torch.softmax(outputs, dim=1)
                    confidence, pred    = torch.max(probs, dim=1)
                    confidence          = confidence.item()
                    pred_id             = pred.item()

                if confidence < CONFIDENCE_THRESHOLD:
                    pred_label = "Uncertain"
                else:
                    pred_label = LABELS_COLS[pred_id]

                print(
                    f"✅ Prediction : {pred_label:15} "
                    f"(confidence={confidence:.4f})"
                )

                # ── Alerte Wazuh uniquement si attaque détectée
                if pred_label not in ("Benign", "Uncertain"):
                    network_info = extract_network_info(current_window)
                    write_wazuh_alert(
                        pred_label   = pred_label,
                        confidence   = round(confidence, 4),
                        network_info = network_info,
                        source_csv   = os.path.basename(file_path),
                    )

                result = {
                    "prediction_id"   : pred_id,
                    "prediction_label": pred_label,
                    "confidence"      : round(confidence, 4),
                    "used_flows"      : WINDOW,
                    "last_csv"        : os.path.basename(file_path),
                }
                prediction_results.append(result)
                pd.DataFrame(prediction_results).to_csv(OUTPUT_PATH, index=False)

            except Exception as e:
                print(f"❌ Erreur IA : {e}")

            buffer_df = buffer_df.iloc[10:].reset_index(drop=True)

    time.sleep(5)