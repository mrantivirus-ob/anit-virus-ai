#!/usr/bin/env python3
import os
import sys
import subprocess
import tempfile
import pathlib
import pandas as pd
import numpy as np
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import cross_val_score, StratifiedKFold
import joblib

ROOT = pathlib.Path(__file__).resolve().parent.parent
EXPORT_BIN = ROOT / 'export_features'
DATA_DIR = ROOT / 'data'
MODEL_DIR = ROOT / 'models'
MODEL_DIR.mkdir(parents=True, exist_ok=True)

def ensure_exporter():
    if not EXPORT_BIN.exists():
        print('Building export_features...')
        # Build with TEST_RUNNER so we get FileFeatureExtractor implementation
        r = subprocess.run(['g++', '-std=c++17', '-O2', '-DTEST_RUNNER', str(ROOT / 'tools' / 'export_features.cpp'), str(ROOT / 'engine.cpp'), '-o', str(EXPORT_BIN)])
        if r.returncode != 0:
            print('Failed to build export_features')
            sys.exit(1)


def export_dir(label, dirpath):
    out = []
    files = list(pathlib.Path(dirpath).glob('*'))
    if not files:
        return out
    args = [str(EXPORT_BIN), str(label)] + [str(p) for p in files]
    print('Running:', ' '.join(args[:3]), '... {} files'.format(len(files)))
    p = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    stdout, stderr = p.communicate()
    if stderr:
        print(stderr)
    for line in stdout.splitlines():
        parts = line.strip().split(',')
        if len(parts) < 3:
            continue
        path = parts[0]
        label = int(parts[1])
        feats = list(map(float, parts[2:]))
        out.append((path, label, feats))
    return out


def main():
    ensure_exporter()
    all_rows = []
    all_rows += export_dir(0, DATA_DIR / 'benign')
    all_rows += export_dir(1, DATA_DIR / 'malware')

    if not all_rows:
        print('No exported rows; generate sample dataset first: python3 tools/generate_dataset.py')
        sys.exit(1)

    X = np.array([r[2] for r in all_rows])
    y = np.array([r[1] for r in all_rows])

    print('Dataset size:', X.shape, 'Positives:', y.sum(), 'Negatives:', (y==0).sum())

    # Simple logistic regression
    clf = LogisticRegression(max_iter=1000)
    # Set n_splits to at most the smallest class size (but at least 2)
    from collections import Counter
    cls_counts = Counter(y)
    min_cls = min(cls_counts.values()) if cls_counts else 0
    n_splits = max(2, min(4, min_cls))
    cv = StratifiedKFold(n_splits=n_splits)
    try:
        scores = cross_val_score(clf, X, y, cv=cv, scoring='roc_auc')
        print('Cross-validated AUC:', scores, 'mean:', np.mean(scores))
    except Exception as e:
        print('Cross-validation skipped (not enough data):', e)

    clf.fit(X, y)
    model_path = MODEL_DIR / 'logreg.joblib'
    joblib.dump(clf, model_path)
    print('Saved model to', model_path)

if __name__ == '__main__':
    main()
