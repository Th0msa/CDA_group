import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
from pyts.approximation import SymbolicAggregateApproximation
from sklearn.cluster import KMeans


def pre_process_data(src_path, dest_path):
    df = pd.concat(d[d['Tos'] != 'Background'] for d in pd.read_csv(src_path, delim_whitespace=True, chunksize=10000))
    df['Addr:Port'] = df['Addr:Port'].str.rstrip('_')
    df[['Src_IP', 'Src_Port']] = df['Prot'].str.split(':', n=1, expand=True)
    df[['Dest_IP', 'Dest_Port']] = df['IP'].str.split(':', n=1, expand=True)
    df = df.drop(['Src', 'Packets', 'Bytes', 'Flows', 'Label', 'Labels', 'Prot', 'IP'], axis=1)
    df = df.rename(columns={'flow': 'Time',
                            'start': 'Durat',
                            'Durat': 'Prot',
                            'Addr:Port': 'Flags',
                            'Dst': 'Tos',
                            'IP.1': 'Packets',
                            'Addr:Port.1': 'Bytes',
                            'Flags': 'Flows',
                            'Tos': 'Label'})
    df['Bytes/Packet'] = df.apply(lambda row: float(row['Bytes']) / row['Packets'], axis=1)
    df.to_pickle(dest_path + '.pkl')

def elbow_plot(X, columns):
    for col in columns:
        sse = {}
        for k in range(1, 10):
            sse[k] = KMeans(n_clusters=k).fit(X[col].values.reshape(-1, 1)).inertia_

        f, (ax1) = plt.subplots(1, figsize=(11, 8))
        sns.lineplot(x=list(sse.keys()), y=list(sse.values()), ax=ax1)
        ax1.set(xlabel='Number of cluster')
        ax1.set(ylabel='SSE')
        ax1.set_title('ELBOW plot - {}'.format(col))
        plt.show()


def main():
    # Uncomment for one time loading in and pre-processing
    # pre_process_data('CTU-13-Dataset/10/capture20110818.pcap.netflow.labeled',
    #                  'CTU-13-Dataset/10/pre_processed_data')
    elbow_plot(pd.read_pickle('CTU-13-Dataset/10/pre_processed_data.pkl'), ['Packets', 'Bytes', 'Bytes/Packet'])


if __name__ == '__main__':
    main()
