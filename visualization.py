import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.cluster import KMeans
from sklearn.preprocessing import LabelEncoder, KBinsDiscretizer


def pre_process_data(src_path, dest_path):
    # Read data in chunks because memory cannot load that much that data at once.
    # At the same time, filter out background labeled flows (now in column 'Tos').
    df = pd.concat(d[d['Tos'] != 'Background'] for d in pd.read_csv(src_path, delim_whitespace=True, chunksize=10000))
    # Delete underscores from Flags (now Addr:Port)
    df['Addr:Port'] = df['Addr:Port'].str.strip('_')
    # Split IPs and ports, some have no ports and therefore will get no value
    df[['Src_IP', 'Src_Port']] = df['Prot'].str.split(':', n=1, expand=True)
    df[['Dest_IP', 'Dest_Port']] = df['IP'].str.split(':', n=1, expand=True)
    # Drop useless columns
    df.drop(['Src', 'Packets', 'Bytes', 'Flows', 'Label', 'Labels', 'Prot', 'IP'], axis=1, inplace=True)
    # Rename columns to actual names
    df = df.rename(columns={'flow': 'Time',
                            'start': 'Durat',
                            'Durat': 'Prot',
                            'Addr:Port': 'Flags',
                            'Dst': 'Tos',
                            'IP.1': 'Packets',
                            'Addr:Port.1': 'Bytes',
                            'Flags': 'Flows',
                            'Tos': 'Label'})

    df.to_pickle(dest_path)


def pre_process_df(df):
    # Extra feature Bytes per Packet
    df['Bytes/Packet'] = df.apply(lambda row: float(row['Bytes']) / row['Packets'], axis=1)
<<<<<<< HEAD

    # Extra feature Packets per Minute
    df['Packet/Duration'] = df.apply(lambda row: float(row['Packets']) / row['Durat'] if row['Durat'] != 0 else 0, axis=1)

    # Extra feature Bytes per Minute
    df['Bytes/Duration'] = df.apply(lambda row: float(row['Bytes']) / row['Durat'] if row['Durat'] != 0 else 0, axis=1)

    # Add DateTime column
    df['Datetime'] = pd.to_datetime(df['Date'] + ' ' + df['Time'])

=======
    # Add DateTime column
    df['Datetime'] = pd.to_datetime(df['Date'] + ' ' + df['Time'])
>>>>>>> master
    # Make Label discrete
    df.loc[df['Label'] == 'LEGITIMATE', 'Label'] = 0
    df.loc[df['Label'] == 'Botnet', 'Label'] = 1

    enc_prot = LabelEncoder()
    enc_prot.fit(df['Prot'])
    df['Prot_code'] = enc_prot.transform(df.Prot)

    enc_flags = LabelEncoder()
    enc_flags.fit(df['Flags'])
    df['Flags_code'] = enc_flags.transform(df.Flags)

    return df


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


def discretize_data(X, column, n_bins):
    print('Estimating...')
    est = KBinsDiscretizer(n_bins=n_bins, encode='ordinal')
    y = est.fit_transform(X[column].values.reshape(-1,1))
    print('Plotting...')
    f, (ax1) = plt.subplots(1, figsize=(11, 8))
    sns.lineplot(x=X['Datetime'][:2000], y=y[:,0][:2000], ax=ax1)
    plt.show()


def discretise_data(X, column_name, n_bins):
    X[column_name + '_normalized'] = ((X[column_name] - X[column_name].min()) / (X[column_name].max() - X[column_name].min())) * 100
    step_size = 100 / n_bins
    bins = np.arange(0, 100 + step_size, step_size)
    X[column_name + '_bin'] = pd.cut(x=X[column_name + '_normalized'], bins=bins, labels=np.arange(0, n_bins), include_lowest=True, right=False)
    return X


def main():
    p = 'CTU-13-Dataset/'

    # Uncomment for one time loading in and pre-processing
    # print('Loading in data...')
    # pre_process_data(p + 'capture20110818.pcap.netflow.labeled', p + 'pre_processed_data.pkl')

    df = pd.read_pickle(p + 'pre_processed_data.pkl')

    print('Preprocessing...')
    df = pre_process_df(df)
    discretise_data(df, 'Bytes/Packet', 10)



    # # Plot Barplot for different protocols
    # print('Plotting Protocol Barplot')
    # barplot_vis(df, ['Prot'], encoder_dict)
    #
    # # Plot Distributions for infected and benign cases
    # print('Plotting Distributions')
    # df_infected = df.loc[df['Label'] == 1]
    # df_benign = df.loc[df['Label'] == 0]
    # distr_plot(df_infected, df_benign, ['Bytes', 'Packets', 'Bytes/Packet', 'Durat'])
    #
    # infected_hosts_scenario_10 = ['147.32.84.165', '147.32.84.191' '147.32.84.192', '147.32.84.193',
    #                               '147.32.84.204', '147.32.84.205', '147.32.84.2056', '147.32.84.207',
    #                               '147.32.84.208', '147.32.84.209']
    #
    # discretize_data(df, ['Bytes/Packet'], 2)


if __name__ == '__main__':
    main()
