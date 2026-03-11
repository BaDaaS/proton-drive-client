#!/usr/bin/env bash
set -euo pipefail

uv run python -m proton_drive_client \
    --username danny@leakix.net \
    --decrypt \
    --list-folder \
    Q5lGEyPU3e_yaaaNmLTrcf473DrM1BrhTVWwA6tP7fBUkSdPQBNmzKzjtyyeGvV-spXiLvRRd6bFojK1a4BYhw== \
    rfnfuqgE-a1Y_an2U1s-sUtanSFQtoCnHu3JCqoboiwnuI7vgpCd6dN2NIkLxYGLL8WKJfwqGocIfH1-85DLjw==
