import numpy as np
import pandas as pd
from sklearn.preprocessing import LabelEncoder
import math


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
    # Add DateTime column
    df['Datetime'] = pd.to_datetime(df['Date'] + ' ' + df['Time'])

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


def discretise_data(X, column_names, n_bins):
    step_size = 100 / n_bins
    ordinal_ranks = [int(math.ceil((p / 100) * len(X))) for p in np.arange(0, 100 + step_size, step_size)]
    for column_name in column_names:
        sort_column = np.sort(X[column_name])
        bins = list(map(lambda r: sort_column[r-1] if r != 0 else 0, ordinal_ranks))
        X[column_name + '_code'] = pd.cut(x=X[column_name], bins=bins,  include_lowest=True, labels=np.arange(n_bins))
    return X

def discretise_data2(column, n_bins):
    step_size = 100 / n_bins
    ordinal_ranks = [int(math.ceil((p / 100) * column.shape[0])) for p in np.arange(0, 100 + step_size, step_size)]
    print("ordinal_ranks ", ordinal_ranks)
    sort_column = np.sort(column)
    print(sort_column)
    bins = list(map(lambda r: sort_column[r-1] if r != 0 else 0, ordinal_ranks))
    print("bins ", bins)
    disc_column = pd.cut(x=column, bins=bins,  include_lowest=True, labels=np.arange(n_bins))
    print("disc_column ", disc_column)
    return disc_column


def attribute_mapping(X, column_names):
    data_matrix = X[column_names].to_numpy()
    max_discrete_values = np.max(data_matrix, axis=0)
    start_space_size = np.product(max_discrete_values)
    mapped_column = np.zeros(len(X))
    for i in range(len(X)):
        code = 0
        space_size = start_space_size
        for j in range(len(column_names)):
            code += data_matrix[i][j] * (space_size / max_discrete_values[j])
            space_size = space_size / max_discrete_values[j]
        mapped_column[i] = code
    X['code'] = mapped_column
    return X


if __name__ == '__main__':
    a = np.array([1, 1, 1, 5, 12, 14, 14, 18, 23, 31])
    c = np.array([0, 1, 1, 0, 1, 2, 0, 0, 2, 2])
    b = discretise_data2(a, 5)
    df = pd.DataFrame({'A': b, 'B': c})
    print(df)
    X = attribute_mapping(df, ['A', 'B'])
    print(X)
