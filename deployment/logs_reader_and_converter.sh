#!/bin/bash

INTERFACE="enp0s3"
DUREE_CAPTURE=60

DOSSIER_SORTIE="/home/victim/captures_nids"
DOSSIER_CSV="$DOSSIER_SORTIE/csv_ia"

JSON_MASTER="$DOSSIER_SORTIE/dataset.json"
CSV_MASTER="$DOSSIER_CSV/dataset_Vul_scan.csv"

mkdir -p "$DOSSIER_SORTIE"
mkdir -p "$DOSSIER_CSV"

echo "🚀 NIDS lancé sur $INTERFACE"
echo "📂 CSV IA : $CSV_MASTER"
echo "📄 Wazuh JSON : $JSON_MASTER"

if [ ! -f "$JSON_MASTER" ]; then
    touch "$JSON_MASTER"
    chmod 644 "$JSON_MASTER"
fi

while true; do

    ID=$(date +"%Y%m%d_%H%M%S")

    PCAP_FILE="$DOSSIER_SORTIE/trafic_$ID.pcap"
    CSV_TMP="$DOSSIER_CSV/tmp_$ID.csv"
    JSON_TMP="$DOSSIER_SORTIE/tmp_$ID.json"

    echo "---------------------------------------------------"
    echo "[$ID] 🔵 Capture réseau en cours..."

    sudo tcpdump \
        -i "$INTERFACE" \
        -s 0 \
        -n \
        -tt \
        -G "$DUREE_CAPTURE" \
        -W 1 \
        -w "$PCAP_FILE" \
        > /dev/null 2>&1

    if [ ! -f "$PCAP_FILE" ]; then
        echo "[$ID] ❌ PCAP non généré"
        continue
    fi

    sudo chown victim:victim "$PCAP_FILE"

    echo "[$ID] 🟢 Extraction des features..."

    /home/victim/ia_env/bin/cicflowmeter \
        -f "$PCAP_FILE" \
        -c "$CSV_TMP" \
        > /dev/null 2>&1

    sleep 2

    if [ -s "$CSV_TMP" ]; then

        echo "[$ID] 🟡 Dataset généré ✔"

        # Ajout au CSV maître sans dupliquer l'en-tête
        if [ ! -f "$CSV_MASTER" ]; then
            cp "$CSV_TMP" "$CSV_MASTER"
        else
            tail -n +2 "$CSV_TMP" >> "$CSV_MASTER"
        fi

        # Conversion uniquement des nouveaux flux
        python3 /home/victim/csv_to_json.py \
            "$CSV_TMP" "$JSON_TMP" \
            > /dev/null 2>&1

        if [ -s "$JSON_TMP" ]; then
            cat "$JSON_TMP" >> "$JSON_MASTER"
            echo "[$ID] 📡 JSON envoyé vers Wazuh"
        fi

        rm -f "$JSON_TMP"
        rm -f "$CSV_TMP"
        rm -f "$PCAP_FILE"

    else

        echo "[$ID] ⚠️ Aucun flux détecté"

        rm -f "$CSV_TMP"
        rm -f "$JSON_TMP"
        rm -f "$PCAP_FILE"

    fi

done