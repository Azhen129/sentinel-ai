# Data provenance

The application demo generates **synthetic**, deterministic connection records using
documentation IP address ranges. It does not monitor the visitor's network.
`sample_zeek.jsonl` is a small synthetic Zeek JSON fixture containing 16 failed TCP
connections to different ports. It uses documentation addresses and can be imported
in explicitly enabled local lab mode; it is not a capture or training data.

The ML training pipeline uses the separately downloaded **UCI KDD Cup 1999 10% subset**.
That published benchmark contains historical simulated network traffic and labeled attacks.
It is not private network capture and it is not the application's demo fixture.

- Catalog and license: https://archive.ics.uci.edu/dataset/130/kdd
- Citation: Stolfo, Fan, Lee, Prodromidis, Chan (1999), https://doi.org/10.24432/C51C7N
- Source: https://kdd.ics.uci.edu/databases/kddcup99/kddcup.data_10_percent.gz
- Verified mirror used by scikit-learn: https://ndownloader.figshare.com/files/5976042
- SHA-256: `8045aca0d84e70e622d1148d7df782496f6333bf6eb979a1b0837c42a9fd9561`
- License listed by UCI: CC BY 4.0; attribution required.
- Downloaded source SHA-256 and actual training/evaluation counts: `models/metrics.json`.

Raw downloads belong under ignored `data/raw/` and are not needed for inference.
Use the platform-specific virtual-environment commands in the [training instructions](../README.md#reproduce-training) to reproduce.
The original UCI archive returned HTTP 403 in this environment; the mirror matches
the archive checksum in the official scikit-learn 1.6.1 dataset loader.
