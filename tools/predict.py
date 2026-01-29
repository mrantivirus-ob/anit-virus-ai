#!/usr/bin/env python3
import sys
import pathlib
import joblib
import subprocess
import numpy as np

ROOT = pathlib.Path(__file__).resolve().parent.parent
MODEL_DIR = ROOT / 'models'
# Prefer EMBER exporter when available
EXPORT_BIN = ROOT / ('export_ember_features' if (ROOT / 'export_ember_features').exists() else 'export_features')

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print('Usage: predict.py <file>')
        sys.exit(1)
    path = pathlib.Path(sys.argv[1])
    if not path.exists():
        print('file not found')
        sys.exit(1)

    model_path = MODEL_DIR / 'logreg.joblib'
    if not model_path.exists():
        print('Model not found. Run tools/train_detector.py first.')
        sys.exit(1)

    # Export features for this file
    import csv, tempfile
    p = subprocess.Popen([str(EXPORT_BIN), '0', str(path)], stdout=subprocess.PIPE, text=True)
    out, err = p.communicate()
    if not out.strip():
        print('failed to export features')
        sys.exit(1)
    parts = out.strip().split(',')
    feats = np.array(list(map(float, parts[2:])))

    clf = joblib.load(model_path)
    prob = clf.predict_proba(feats.reshape(1, -1))[0,1]
    print(f'Prediction score: {prob:.4f}')
    print('Label:', 'MALWARE' if prob >= 0.5 else 'BENIGN')
