import pandas as pd
import anomaly_detector
anomaly_detector.load_or_train_model()
df = pd.read_csv('../data/Monday-WorkingHours.pcap_ISCX.csv')
for _, row in df.head(5).iterrows():
    print(anomaly_detector.detect_anomaly(row.to_dict()))
