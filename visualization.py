import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
from pyts.approximation import SymbolicAggregateApproximation
from sklearn.cluster import KMeans
from sklearn.preprocessing import LabelEncoder


def pre_process_data(src_path, dest_path):
    # Read data in chunks because memory cannot load that much that data at once.
    # At the same time parse the date and time (now flow column because data is structured weird)
    # and filter out background labeled flows.
    df = pd.concat(d[d['Tos'] != 'Background'] for d in pd.read_csv(src_path, delim_whitespace=True,
                                                                    chunksize=10000, parse_dates=[['Date', 'flow']]))
    # Delete underscores from Flags (now Addr:Port)
    df['Addr:Port'] = df['Addr:Port'].str.strip('_')
    # Split IPs and ports, some have no ports and therefore will get no value
    df[['Src_IP', 'Src_Port']] = df['Prot'].str.split(':', n=1, expand=True)
    df[['Dest_IP', 'Dest_Port']] = df['IP'].str.split(':', n=1, expand=True)
    # Drop useless columns
    df = df.drop(['Src', 'Packets', 'Bytes', 'Flows', 'Label', 'Labels', 'Prot', 'IP'], axis=1)
    # Rename columns to actual names
    df = df.rename(columns={'Date_flow': 'Datetime',
                            'start': 'Durat',
                            'Durat': 'Prot',
                            'Addr:Port': 'Flags',
                            'Dst': 'Tos',
                            'IP.1': 'Packets',
                            'Addr:Port.1': 'Bytes',
                            'Flags': 'Flows',
                            'Tos': 'Label'})
    # Extra feature Bytes per Packet
    df.to_pickle(dest_path)


def pre_process_df(df):
    df['Bytes/Packet'] = df.apply(lambda row: float(row['Bytes']) / row['Packets'], axis=1)
    df.loc[df['Label'] == 'LEGITIMATE', 'Label'] = 0
    df.loc[df['Label'] == 'Botnet', 'Label'] = 1
    encoder_dict = {}
    obj_cols = ['Prot', 'Flags']
    for c in obj_cols:
        le = LabelEncoder()
        le.fit(df[c])
        df[c] = le.transform(df[c])
        encoder_dict[c] = le
    return df, encoder_dict


def barplot_vis(X, columns, encoder_dict):
    for col in columns:
        df_perc = X[[col, 'Label']].groupby([col]).sum()
        df_perc['perc'] = df_perc['Label'] / (X[col].value_counts(dropna=False)) * 100
        df_perc['rel_perc'] = df_perc['Label'] / (X['Label'].sum()) * 100
        df_perc = df_perc.drop('Label', axis=1)
        f, (ax1) = plt.subplots(1, figsize=(11, 8))
        df_perc.plot.bar(ax=ax1)
        ax1.set_xticklabels(encoder_dict.get(col).inverse_transform(df_perc.index))
        ax1.legend(["#protocol/total_protocol", "#protocol/total_infected"])
        ax1.set(ylabel='Infected (%)')
        ax1.set(xlabel='Protocol')
        plt.show()


def distr_plot(X_infected, X_benign, columns):
    for col in columns:
        f, (ax1, ax2) = plt.subplots(1, 2, figsize=(22, 8))

        sns.distplot(X_infected[col], ax=ax1)
        ax1.set_title('Infected Distribution {}'.format(col))

        sns.distplot(X_benign[col], ax=ax2)
        ax2.set_title('Benign Distribution {}'.format(col))
        plt.show()


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
    p = 'CTU-13-Dataset/10/'

    # Uncomment for one time loading in and pre-processing
    # print('Loading in data...')
    # pre_process_data(p + 'capture20110818.pcap.netflow.labeled',
    #                  p+ 'pre_processed_data.pkl')

    df = pd.read_pickle(p + 'pre_processed_data.pkl')

    print('Preprocessing...')
    df, encoder_dict = pre_process_df(df)

    # Plot Barplot for different protocols
    print('Plotting Protocol Barplot')
    barplot_vis(df, ['Prot'], encoder_dict)

    # Plot Distributions for infected and benign cases
    print('Plotting Distributions')
    df_infected = df.loc[df['Label'] == 1]
    df_benign = df.loc[df['Label'] == 0]
    distr_plot(df_infected, df_benign, ['Bytes', 'Packets', 'Bytes/Packet', 'Durat'])

    # Plot ELBOWs for Packets, Bytes and Bytes/Packet
    print('Plotting ELBOWs')
    elbow_plot(df, ['Packets', 'Bytes', 'Bytes/Packet'])

    infected_hosts_scenario_10 = ['147.32.84.165', '147.32.84.191' '147.32.84.192', '147.32.84.193',
                                  '147.32.84.204', '147.32.84.205', '147.32.84.2056', '147.32.84.207',
                                  '147.32.84.208', '147.32.84.209']

if __name__ == '__main__':
    main()
