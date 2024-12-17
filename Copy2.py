#!/usr/bin/env python
# coding: utf-8

# In[1]:


import numpy as np
import pandas as pd
import seaborn as sns
import missingno as msno
sns.set(style='darkgrid')
import matplotlib.pyplot as plt


# In[2]:


import pandas as pd
data1 = pd.read_csv('Sisira/trial new/Monday-WorkingHours.pcap_ISCX.csv')
data2 = pd.read_csv('Sisira/trial new/Tuesday-WorkingHours.pcap_ISCX.csv')
data3 = pd.read_csv('Sisira/trial new/Wednesday-workingHours.pcap_ISCX.csv')
data4 = pd.read_csv('Sisira/trial new/Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv')
data5 = pd.read_csv('Sisira/trial new/Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv')
data6 = pd.read_csv('Sisira/trial new/Friday-WorkingHours-Morning.pcap_ISCX.csv')
data7 = pd.read_csv('Sisira/trial new/Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv')
data8 = pd.read_csv('Sisira/trial new/Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv')
     


# In[3]:


data_list = [data1, data2, data3, data4, data5, data6, data7, data8]

print('Data dimensions: ')
for i, data in enumerate(data_list, start = 1):
  rows, cols = data.shape
  print(f'Data{i} -> {rows} rows, {cols} columns')


# In[4]:


data = pd.concat(data_list)
rows, cols = data.shape

print('New dimension:')
print(f'Number of rows: {rows}')
print(f'Number of columns: {cols}')
print(f'Total cells: {rows * cols}')


# In[5]:


# Deleting dataframes after concating to save memory
for d in data_list: del d


# In[6]:


# Renaming the columns by removing leading/trailing whitespace
col_names = {col: col.strip() for col in data.columns}
data.rename(columns = col_names, inplace = True)


# In[7]:


data.columns


# In[8]:


data.info()


# In[9]:


pd.options.display.max_rows = 80

print('Overview of Columns:')
data.describe().transpose()


# In[10]:


pd.options.display.max_columns = 80
data


# In[11]:


#data cleaning
#identifying duplicate values
dups = data[data.duplicated()]
print(f'Number of duplicates: {len(dups)}')


# In[12]:


data.drop_duplicates(inplace = True)
data.shape


# In[13]:


#identifying missing values
missing_val = data.isna().sum()
print(missing_val.loc[missing_val > 0])


# In[14]:


# Checking for infinity values
numeric_cols = data.select_dtypes(include = np.number).columns
inf_count = np.isinf(data[numeric_cols]).sum()
print(inf_count[inf_count > 0])


# In[15]:


# Replacing any infinite values (positive or negative) with NaN (not a number)
print(f'Initial missing values: {data.isna().sum().sum()}')

data.replace([np.inf, -np.inf], np.nan, inplace = True)

print(f'Missing values after processing infinite values: {data.isna().sum().sum()}')


# In[16]:


missing = data.isna().sum()
print(missing.loc[missing > 0])


# In[17]:


# Calculating missing value percentage in the dataset
mis_per = (missing / len(data)) * 100
mis_table = pd.concat([missing, mis_per.round(2)], axis = 1)
mis_table = mis_table.rename(columns = {0 : 'Missing Values', 1 : 'Percentage of Total Values'})

print(mis_table.loc[mis_per > 0])


# In[18]:


#Visualization of missing data
sns.set_palette('pastel')
colors = sns.color_palette()

missing_vals = [col for col in data.columns if data[col].isna().any()]

fig, ax = plt.subplots(figsize = (2, 6))
msno.bar(data[missing_vals], ax = ax, fontsize = 12, color = colors)
ax.set_xlabel('Features', fontsize = 12)
ax.set_ylabel('Non-Null Value Count', fontsize = 12)
ax.set_title('Missing Value Chart', fontsize = 12)
plt.show()


# In[19]:


#Dealing with missing values (Columns with missing data)
import matplotlib.pyplot as plt
import seaborn as sns

# Drop missing or non-numeric values
data['Flow Bytes/s'] = pd.to_numeric(data['Flow Bytes/s'], errors='coerce')
data = data.dropna(subset=['Flow Bytes/s'])

# Reset index to handle any duplicate indices
data = data.reset_index(drop=True)

# Plot the boxplot
plt.figure(figsize=(8, 3))
sns.boxplot(x=data['Flow Bytes/s'])
plt.xlabel('Boxplot of Flow Bytes/s')
plt.show()


# In[20]:


colors = sns.color_palette('Blues')
plt.hist(data['Flow Bytes/s'], color = colors[1])
plt.title('Histogram of Flow Bytes/s')
plt.xlabel('Flow Bytes/s')
plt.ylabel('Frequency')
plt.show()


# In[21]:


plt.figure(figsize = (8, 3))
sns.boxplot(x = data['Flow Packets/s'])
plt.xlabel('Boxplot of Flow Packets/s')
plt.show()


# In[22]:


plt.hist(data['Flow Packets/s'], color = colors[1])
plt.title('Histogram of Flow Packets/s')
plt.xlabel('Flow Packets/s')
plt.ylabel('Frequency')
plt.show()


# In[23]:


med_flow_bytes = data['Flow Bytes/s'].median()
med_flow_packets = data['Flow Packets/s'].median()

print('Median of Flow Bytes/s: ', med_flow_bytes)
print('Median of Flow Packets/s: ', med_flow_packets)


# In[24]:


# Filling missing values with median
data['Flow Bytes/s'] = data['Flow Bytes/s'].fillna(med_flow_bytes)
data['Flow Packets/s'] = data['Flow Packets/s'].fillna(med_flow_packets)

# Optional: Verify there are no missing values left in these columns
print(f"Missing values in 'Flow Bytes/s': {data['Flow Bytes/s'].isnull().sum()}")
print(f"Missing values in 'Flow Packets/s': {data['Flow Packets/s'].isnull().sum()}")


# In[25]:


data['Label'].unique()


# In[26]:


# Types of attacks & normal instances (BENIGN)
data['Label'].value_counts()


# In[27]:


# Creating a dictionary that maps each label to its attack type
attack_map = {
    'BENIGN': 'BENIGN',
    'DDoS': 'DDoS',
    'DoS Hulk': 'DoS',
    'DoS GoldenEye': 'DoS',
    'DoS slowloris': 'DoS',
    'DoS Slowhttptest': 'DoS',
    'PortScan': 'Port Scan',
    'FTP-Patator': 'Brute Force',
    'SSH-Patator': 'Brute Force',
    'Bot': 'Bot',
    'Web Attack � Brute Force': 'Web Attack',
    'Web Attack � XSS': 'Web Attack',
    'Web Attack � Sql Injection': 'Web Attack',
    'Infiltration': 'Infiltration',
    'Heartbleed': 'Heartbleed'
}

# Creating a new column 'Attack Type' in the DataFrame based on the attack_map dictionary
data['Attack Type'] = data['Label'].map(attack_map)
data['Attack Type'].value_counts()


# In[28]:


data.drop('Label', axis = 1, inplace = True)


# In[29]:


from sklearn.preprocessing import LabelEncoder

le = LabelEncoder()
data['Attack Number'] = le.fit_transform(data['Attack Type'])

print(data['Attack Number'].unique())


# In[30]:


# Printing corresponding attack type for each encoded value
encoded_values = data['Attack Number'].unique()
for val in sorted(encoded_values):
    print(f"{val}: {le.inverse_transform([val])[0]}")


# In[31]:


corr = data.corr(numeric_only = True).round(2)
corr.style.background_gradient(cmap = 'coolwarm', axis = None).format(precision = 2)
fig, ax = plt.subplots(figsize = (24, 24))
sns.heatmap(corr, cmap = 'coolwarm', annot = False, linewidth = 0.5)
plt.title('Correlation Matrix', fontsize = 18)
plt.show()


# In[32]:


# Positive correlation features for 'Attack Number'
pos_corr_features = corr['Attack Number'][(corr['Attack Number'] > 0) & (corr['Attack Number'] < 1)].index.tolist()

print("Features with positive correlation with 'Attack Number':\n")
for i, feature in enumerate(pos_corr_features, start = 1):
    corr_value = corr.loc[feature, 'Attack Number']
    print('{:<3} {:<24} :{}'.format(f'{i}.', feature, corr_value))


# In[33]:


print(f'Number of considerable important features: {len(pos_corr_features)}')


# In[34]:


# Checking for columns with zero standard deviation (the blank squares in the heatmap)
std = data.std(numeric_only = True)
zero_std_cols = std[std == 0].index.tolist()
zero_std_cols


# In[35]:


# Data sampling for data analysis
sample_size = int(0.2 * len(data)) # 20% of the original size
sampled_data = data.sample(n = sample_size, replace = False, random_state = 0)
sampled_data.shape


# In[36]:


# To assess if a sample is representative of the population and comparison of descriptive statistics (mean)
numeric_cols = data.select_dtypes(include = [np.number]).columns.tolist()
print('Descriptive Statistics Comparison (mean):\n')
print('{:<32s}{:<22s}{:<22s}{}'.format('Feature', 'Original Dataset', 'Sampled Dataset', 'Variation Percentage'))
print('-' * 96)

high_variations = []
for col in numeric_cols:
    old = data[col].describe()[1]
    new = sampled_data[col].describe()[1]
    if old == 0:
        pct = 0
    else:
        pct = abs((new - old) / old)
    if pct * 100 > 5:
        high_variations.append((col, pct * 100))
    print('{:<32s}{:<22.6f}{:<22.6f}{:<2.2%}'.format(col, old, new, pct))


# In[37]:


labels = [t[0] for t in high_variations]
values = [t[1] for t in high_variations]

colors = sns.color_palette('Blues', n_colors=len(labels))
fig, ax = plt.subplots(figsize = (10, 5))
ax.bar(labels, values, color = colors)

for i in range(len(labels)):
    ax.text(i, values[i], str(round(values[i], 2)), ha = 'center', va = 'bottom', fontsize = 10)

plt.xticks(rotation = 90)
ax.set_title('Variation percenatge of the features of the sample which\n mean value variates higher than 5% of the actual mean')
ax.set_ylabel('Percentage (%)')
ax.set_yticks(np.arange(0, 41, 5))
plt.show()


# In[38]:


# Printing the unique value count
indent = '{:<3} {:<30}: {}'
print('Unique value count for: ')
for i, feature in enumerate(list(sampled_data.columns)[:-1], start = 1):
    print(indent.format(f'{i}.', feature, sampled_data[feature].nunique()))


# In[39]:


# Original dataset size
print(f"Original dataset size: {len(data)}")

# Calculated sample size
sample_size = int(0.2 * len(data))
print(f"Calculated sample size: {sample_size}")

# Sampled dataset size
sampled_data = data.sample(n=sample_size, replace=False, random_state=0)
print(f"Sampled dataset size: {sampled_data.shape[0]}")

# Compare missing values and check for preprocessing
print(data.isnull().sum())


# In[40]:


# Data sampling for data analysis
sample_size = int(0.2 * len(data)) # 20% of the original size
sampled_data = data.sample(n = sample_size, replace = False, random_state = 0)
sampled_data.shape


# In[41]:


print(f"Dataset length: {len(data)}")


# In[42]:


'''Generating a set of visualizations for columns that have more than one unique value but less than 50 unique values.
For categorical columns, a bar plot is generated showing the count of each unique value.
For numerical columns, a histogram is generated.'''
unique_values = sampled_data.nunique()
selected_cols = sampled_data[[col for col in sampled_data if 1 < unique_values[col] < 50]]
rows, cols = selected_cols.shape
col_names = list(selected_cols)
num_of_rows = (cols + 3) // 4

color_palette = sns.color_palette('Blues', n_colors = 3)
plt.figure(figsize = (6 * 4, 8 * num_of_rows))

for i in range(cols):
    plt.subplot(num_of_rows, 4, i + 1)
    col_data = selected_cols.iloc[:, i]
    if col_data.dtype.name == 'object':
        col_data.value_counts().plot(kind = 'bar', color = color_palette[2])
    else:
        col_data.hist(color = color_palette[0])

    plt.ylabel('Count')
    plt.xticks(rotation = 90)
    plt.title(col_names[i])

plt.tight_layout()
plt.show()


# In[43]:


# Correlation matrix for sampled data
corr_matrix = sampled_data.corr(numeric_only = True).round(2)
corr_matrix.style.background_gradient(cmap = 'coolwarm', axis = None).format(precision = 2)


# In[44]:


# Plotting the pairs of strongly positive correlated features in the sampled_data that have a correlation coefficient of 0.85 or higher
cols = list(sampled_data.columns)[:-2]
high_corr_pairs = []
corr_th = 0.85

for i in range(len(cols)):
  for j in range(i + 1, len(cols)):
    val = sampled_data[cols[i]].corr(sampled_data[cols[j]])
    # If the correlation coefficient is NaN or below the threshold, skip to the next pair
    if np.isnan(val) or val < corr_th:
      continue
    high_corr_pairs.append((val, cols[i], cols[j]))

size, cols = len(high_corr_pairs), 4
rows, rem =  size // cols, size % cols
if rem:
  rows += 1

fig, axs = plt.subplots(rows, cols, figsize = (24, int(size * 1.7)))
for i in range(rows):
    for j in range(cols):
      try:
        val, x, y = high_corr_pairs[i * cols + j]
        if val > 0.99:
          axs[i, j].scatter(sampled_data[x], sampled_data[y], color = 'green', alpha = 0.1)
        else:
          axs[i, j].scatter(sampled_data[x], sampled_data[y], color = 'blue', alpha = 0.1)
        axs[i, j].set_xlabel(x)
        axs[i, j].set_ylabel(y)
        axs[i, j].set_title(f'{x} vs\n{y} ({val:.2f})')
      except IndexError:
        fig.delaxes(axs[i, j])

fig.tight_layout()
plt.show()


# In[45]:


sampled_data.drop('Attack Number', axis = 1, inplace = True)
data.drop('Attack Number', axis = 1, inplace = True)


# In[46]:


# Identifying outliers
numeric_data = sampled_data.select_dtypes(include = ['float', 'int'])
q1 = numeric_data.quantile(0.25)
q3 = numeric_data.quantile(0.75)
iqr = q3 - q1
outlier = (numeric_data < (q1 - 1.5 * iqr)) | (numeric_data > (q3 + 1.5 * iqr))
outlier_count = outlier.sum()
outlier_percentage = round(outlier.mean() * 100, 2)
outlier_stats = pd.concat([outlier_count, outlier_percentage], axis = 1)
outlier_stats.columns = ['Outlier Count', 'Outlier Percentage']

print(outlier_stats)


# In[47]:


# Identifying outliers based on attack type
outlier_counts = {}
for i in numeric_data:
    for attack_type in sampled_data['Attack Type'].unique():
        attack_data = sampled_data[i][sampled_data['Attack Type'] == attack_type]
        q1, q3 = np.percentile(attack_data, [25, 75])
        iqr = q3 - q1
        lower_bound = q1 - 1.5 * iqr
        upper_bound = q3 + 1.5 * iqr
        num_outliers = ((attack_data < lower_bound) | (attack_data > upper_bound)).sum()
        outlier_percent = num_outliers / len(attack_data) * 100
        outlier_counts[(i, attack_type)] = (num_outliers, outlier_percent)

for i in numeric_data:
  print(f'Feature: {i}')
  for attack_type in sampled_data['Attack Type'].unique():
    num_outliers, outlier_percent = outlier_counts[(i, attack_type)]
    print(f'- {attack_type}: {num_outliers} ({outlier_percent:.2f}%)')
  print()


# In[48]:


# Plotting the percentage of outliers that are higher than 20%
fig, ax = plt.subplots(figsize = (24, 10))
for i in numeric_data:
    for attack_type in sampled_data['Attack Type'].unique():
        num_outliers, outlier_percent = outlier_counts[(i, attack_type)]
        if outlier_percent > 20:
            ax.bar(f'{i} - {attack_type}', outlier_percent)

ax.set_xlabel('Feature-Attack Type')
ax.set_ylabel('Percentage of Outliers')
ax.set_title('Outlier Analysis')
ax.set_yticks(np.arange(0, 41, 10))
plt.xticks(rotation = 90)
plt.show()


# In[49]:


# Different 'Attack Type' in the main dataset excluding 'BENIGN'
attacks = data.loc[data['Attack Type'] != 'BENIGN']

plt.figure(figsize = (10, 6))
ax = sns.countplot(x = 'Attack Type', data = attacks, palette = 'pastel', order = attacks['Attack Type'].value_counts().index)
plt.title('Types of attacks')
plt.xlabel('Attack Type')
plt.ylabel('Count')
plt.xticks(rotation = 90)

for p in ax.patches:
    ax.annotate(f'{p.get_height():.0f}', (p.get_x() + p.get_width() / 2, p.get_height() + 1000), ha = 'center')

plt.show()


# In[50]:


attack_counts = attacks['Attack Type'].value_counts()
threshold = 0.005
percentages = attack_counts / attack_counts.sum()
small_slices = percentages[percentages < threshold].index.tolist()
attack_counts['Other'] = attack_counts[small_slices].sum()
attack_counts.drop(small_slices, inplace = True)

sns.set_palette('pastel')
plt.figure(figsize = (8, 8))
plt.pie(attack_counts.values, labels = attack_counts.index, autopct = '%1.1f%%', textprops={'fontsize': 6})
plt.title('Distribution of Attack Types')
plt.legend(attack_counts.index, loc = 'best')
plt.show()


# In[51]:


# Creating a boxplot for each attack type with the columns of sampled dataset
for attack_type in sampled_data['Attack Type'].unique():
    attack_data = sampled_data[sampled_data['Attack Type'] == attack_type]
    plt.figure(figsize=(20, 20))
    sns.boxplot(data = attack_data.drop(columns = ['Attack Type']), orient = 'h')
    plt.title(f'Boxplot of Features for Attack Type: {attack_type}')
    plt.xlabel('Feature Value')
    plt.show()


# In[52]:


data.groupby('Attack Type').first()


# In[53]:


# For improving performance and reduce memory-related errors
old_memory_usage = data.memory_usage().sum() / 1024 ** 2
print(f'Initial memory usage: {old_memory_usage:.2f} MB')
for col in data.columns:
    col_type = data[col].dtype
    if col_type != object:
        c_min = data[col].min()
        c_max = data[col].max()
        # Downcasting float64 to float32
        if str(col_type).find('float') >= 0 and c_min > np.finfo(np.float32).min and c_max < np.finfo(np.float32).max:
            data[col] = data[col].astype(np.float32)

        # Downcasting int64 to int32
        elif str(col_type).find('int') >= 0 and c_min > np.iinfo(np.int32).min and c_max < np.iinfo(np.int32).max:
            data[col] = data[col].astype(np.int32)

new_memory_usage = data.memory_usage().sum() / 1024 ** 2
print(f"Final memory usage: {new_memory_usage:.2f} MB")


# In[54]:


# Calculating percentage reduction in memory usage
print(f'Reduced memory usage: {1 - (new_memory_usage / old_memory_usage):.2%}')


# In[55]:


data.info()


# In[56]:


# Dropping columns with only one unique value
num_unique = data.nunique()
one_variable = num_unique[num_unique == 1]
not_one_variable = num_unique[num_unique > 1].index

dropped_cols = one_variable.index
data = data[not_one_variable]

print('Dropped columns:')
dropped_cols


# In[57]:


data.describe().transpose()


# In[58]:


data.shape


# In[59]:


# Columns after removing non variant columns
data.columns


# In[60]:


# Standardizing the dataset
from sklearn.preprocessing import StandardScaler

features = data.drop('Attack Type', axis = 1)
attacks = data['Attack Type']

scaler = StandardScaler()
scaled_features = scaler.fit_transform(features)


# In[61]:


from sklearn.decomposition import IncrementalPCA

size = len(features.columns) // 2
ipca = IncrementalPCA(n_components = size, batch_size = 500)
for batch in np.array_split(scaled_features, len(features) // 500):
    ipca.partial_fit(batch)

print(f'information retained: {sum(ipca.explained_variance_ratio_):.2%}')


# In[62]:


transformed_features = ipca.transform(scaled_features)
new_data = pd.DataFrame(transformed_features, columns = [f'PC{i+1}' for i in range(size)])
new_data['Attack Type'] = attacks.values


# In[63]:


type(new_data)


# In[64]:


print(new_data.head())


# In[ ]:


import pandas as pd

# Assuming your cleaned and standardized data is available in a DataFrame named 'new_data'

# Save the DataFrame to a CSV file
new_data.to_csv("standardized_data.csv", index=False)

print("Standardized data saved as 'standardized_data.csv'")


# In[ ]:


import pandas as pd

# Load the dataset
data = pd.read_csv("standardized_data.csv")

# Split the dataset into 5 groups of features (ensure the last column is the target/label)
features = data.iloc[:, :-1]  # All columns except the last
labels = data.iloc[:, -1]  # Target column

# Number of clients
num_clients = 5

# Calculate columns per client
cols_per_client = features.shape[1] // num_clients

# Create subsets of features for each client (last column as labels must be appended to each)
clients_data = [
    pd.concat([features.iloc[:, i * cols_per_client:(i + 1) * cols_per_client], labels], axis=1)
    for i in range(num_clients)
]

# Save each client's data to a CSV file
for i, client_data in enumerate(clients_data, 1):
    client_data.to_csv(f"client_{i}_vertical_data.csv", index=False)
    print(f"Client {i} vertical data saved as 'client_{i}_vertical_data.csv'")


# In[68]:


import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    precision_score,
    recall_score,
    f1_score
)

# Load Client 1's data
client1_data = pd.read_csv("Sisira Vertical split/client_1_vertical_data.csv")

# Separate features and target
X = client1_data.iloc[:, :-1]  # All columns except the last (features)
y = client1_data.iloc[:, -1]   # Last column (target)

# Split the data into train and test sets
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# Initialize Random Forest Classifier
rf_model_1 = RandomForestClassifier(random_state=42)

# Train the model
rf_model_1.fit(X_train, y_train)

# Predict on test set
y_pred = rf_model_1.predict(X_test)

# Evaluate the model
accuracy = accuracy_score(y_test, y_pred)
precision = precision_score(y_test, y_pred, average="weighted")
recall = recall_score(y_test, y_pred, average="weighted")
f1 = f1_score(y_test, y_pred, average="weighted")

# Confusion Matrix
conf_matrix = confusion_matrix(y_test, y_pred)

# Extracting True Positives, False Positives, True Negatives, and False Negatives for each class
TP = conf_matrix.diagonal()  # True Positives per class
FP = conf_matrix.sum(axis=0) - conf_matrix.diagonal()  # False Positives per class
FN = conf_matrix.sum(axis=1) - conf_matrix.diagonal()  # False Negatives per class
TN = conf_matrix.sum() - (FP + FN + TP)  # True Negatives per class

# Print metrics
print("Confusion Matrix:\n", conf_matrix)
print(f"Accuracy: {accuracy * 100:.2f}%")
print(f"Precision: {precision:.2f}")
print(f"Recall: {recall:.2f}")
print(f"F1 Score: {f1:.2f}")

print("\nDetailed Classification Report:\n", classification_report(y_test, y_pred))

# Print detailed counts for each class
print("\nTrue Positives per class:", TP)
print("False Positives per class:", FP)
print("False Negatives per class:", FN)
print("True Negatives per class:", TN)

# Overall sums
print("\nTotal True Positives:", TP.sum())
print("Total False Positives:", FP.sum())
print("Total True Negatives:", TN.sum())
print("Total False Negatives:", FN.sum())


# In[69]:


import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    precision_score,
    recall_score,
    f1_score
)

# Load Client 2's data
client2_data = pd.read_csv("Sisira Vertical split/client_2_vertical_data.csv")

# Separate features and target
X = client2_data.iloc[:, :-1]  # All columns except the last (features)
y = client2_data.iloc[:, -1]   # Last column (target)

# Split the data into train and test sets
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# Initialize Random Forest Classifier
rf_model_2 = RandomForestClassifier(random_state=42)

# Train the model
rf_model_2.fit(X_train, y_train)

# Predict on test set
y_pred = rf_model_2.predict(X_test)

# Evaluate the model
accuracy = accuracy_score(y_test, y_pred)
precision = precision_score(y_test, y_pred, average="weighted")
recall = recall_score(y_test, y_pred, average="weighted")
f1 = f1_score(y_test, y_pred, average="weighted")

# Confusion Matrix
conf_matrix = confusion_matrix(y_test, y_pred)

# Extracting True Positives, False Positives, True Negatives, and False Negatives for each class
TP = conf_matrix.diagonal()  # True Positives per class
FP = conf_matrix.sum(axis=0) - conf_matrix.diagonal()  # False Positives per class
FN = conf_matrix.sum(axis=1) - conf_matrix.diagonal()  # False Negatives per class
TN = conf_matrix.sum() - (FP + FN + TP)  # True Negatives per class

# Print metrics
print("Confusion Matrix:\n", conf_matrix)
print(f"Accuracy: {accuracy * 100:.2f}%")
print(f"Precision: {precision:.2f}")
print(f"Recall: {recall:.2f}")
print(f"F1 Score: {f1:.2f}")

print("\nDetailed Classification Report:\n", classification_report(y_test, y_pred))

# Print detailed counts for each class
print("\nTrue Positives per class:", TP)
print("False Positives per class:", FP)
print("False Negatives per class:", FN)
print("True Negatives per class:", TN)

# Overall sums
print("\nTotal True Positives:", TP.sum())
print("Total False Positives:", FP.sum())
print("Total True Negatives:", TN.sum())
print("Total False Negatives:", FN.sum())


# In[70]:


import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    precision_score,
    recall_score,
    f1_score
)

# Load Client 3's data
client3_data = pd.read_csv("Sisira Vertical split/client_3_vertical_data.csv")

# Separate features and target
X = client3_data.iloc[:, :-1]  # All columns except the last (features)
y = client3_data.iloc[:, -1]   # Last column (target)

# Split the data into train and test sets
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# Initialize Random Forest Classifier
rf_model_3 = RandomForestClassifier(random_state=42)

# Train the model
rf_model_3.fit(X_train, y_train)

# Predict on test set
y_pred = rf_model_3.predict(X_test)

# Evaluate the model
accuracy = accuracy_score(y_test, y_pred)
precision = precision_score(y_test, y_pred, average="weighted")
recall = recall_score(y_test, y_pred, average="weighted")
f1 = f1_score(y_test, y_pred, average="weighted")

# Confusion Matrix
conf_matrix = confusion_matrix(y_test, y_pred)

# Extracting True Positives, False Positives, True Negatives, and False Negatives
TP = conf_matrix.diagonal().sum()  # True Positives (Sum of diagonal values)
FP = conf_matrix.sum(axis=0) - conf_matrix.diagonal()  # False Positives
FN = conf_matrix.sum(axis=1) - conf_matrix.diagonal()  # False Negatives
TN = conf_matrix.sum() - (FP + FN + TP)  # True Negatives

# Print metrics
print("Confusion Matrix:\n", conf_matrix)
print(f"Accuracy: {accuracy * 100:.2f}%")
print(f"Precision: {precision:.2f}")
print(f"Recall: {recall:.2f}")
print(f"F1 Score: {f1:.2f}")

print("\nDetailed Classification Report:\n", classification_report(y_test, y_pred))

print("\nTrue Positives:", TP)
print("False Positives:", FP.sum())
print("True Negatives:", TN.sum())
print("False Negatives:", FN.sum())


# In[71]:


import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    precision_score,
    recall_score,
    f1_score
)

# Load Client 4's data
client4_data = pd.read_csv("Sisira Vertical split/client_4_vertical_data.csv")

# Separate features and target
X = client4_data.iloc[:, :-1]  # All columns except the last (features)
y = client4_data.iloc[:, -1]   # Last column (target)

# Split the data into train and test sets
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# Initialize Random Forest Classifier
rf_model_4 = RandomForestClassifier(random_state=42)

# Train the model
rf_model_4.fit(X_train, y_train)

# Predict on test set
y_pred = rf_model_4.predict(X_test)

# Evaluate the model
accuracy = accuracy_score(y_test, y_pred)
precision = precision_score(y_test, y_pred, average="weighted")
recall = recall_score(y_test, y_pred, average="weighted")
f1 = f1_score(y_test, y_pred, average="weighted")

# Confusion Matrix
conf_matrix = confusion_matrix(y_test, y_pred)

# Extracting True Positives, False Positives, True Negatives, and False Negatives
TP = conf_matrix.diagonal().sum()  # True Positives (Sum of diagonal values)
FP = conf_matrix.sum(axis=0) - conf_matrix.diagonal()  # False Positives
FN = conf_matrix.sum(axis=1) - conf_matrix.diagonal()  # False Negatives
TN = conf_matrix.sum() - (FP + FN + TP)  # True Negatives

# Print metrics
print("Confusion Matrix:\n", conf_matrix)
print(f"Accuracy: {accuracy * 100:.2f}%")
print(f"Precision: {precision:.2f}")
print(f"Recall: {recall:.2f}")
print(f"F1 Score: {f1:.2f}")

print("\nDetailed Classification Report:\n", classification_report(y_test, y_pred))

print("\nTrue Positives:", TP)
print("False Positives:", FP.sum())
print("True Negatives:", TN.sum())
print("False Negatives:", FN.sum())


# In[72]:


import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    precision_score,
    recall_score,
    f1_score
)

# Load Client 5's data
client5_data = pd.read_csv("Sisira Vertical split/client_5_vertical_data.csv")

# Separate features and target
X = client5_data.iloc[:, :-1]  # All columns except the last (features)
y = client5_data.iloc[:, -1]   # Last column (target)

# Split the data into train and test sets
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# Initialize Random Forest Classifier
rf_model_5 = RandomForestClassifier(random_state=42)

# Train the model
rf_model_5.fit(X_train, y_train)

# Predict on test set
y_pred = rf_model_5.predict(X_test)

# Evaluate the model
accuracy = accuracy_score(y_test, y_pred)
precision = precision_score(y_test, y_pred, average="weighted")
recall = recall_score(y_test, y_pred, average="weighted")
f1 = f1_score(y_test, y_pred, average="weighted")

# Confusion Matrix
conf_matrix = confusion_matrix(y_test, y_pred)

# Extracting True Positives, False Positives, True Negatives, and False Negatives
TP = conf_matrix.diagonal().sum()  # True Positives (Sum of diagonal values)
FP = conf_matrix.sum(axis=0) - conf_matrix.diagonal()  # False Positives
FN = conf_matrix.sum(axis=1) - conf_matrix.diagonal()  # False Negatives
TN = conf_matrix.sum() - (FP + FN + TP)  # True Negatives

# Print metrics
print("Confusion Matrix:\n", conf_matrix)
print(f"Accuracy: {accuracy * 100:.2f}%")
print(f"Precision: {precision:.2f}")
print(f"Recall: {recall:.2f}")
print(f"F1 Score: {f1:.2f}")

print("\nDetailed Classification Report:\n", classification_report(y_test, y_pred))

print("\nTrue Positives:", TP)
print("False Positives:", FP.sum())
print("True Negatives:", TN.sum())
print("False Negatives:", FN.sum())


# In[79]:


import joblib

# Save the trained Random Forest models for each client
joblib.dump(rf_model_1, 'Sisira Vertical split/client_1_rf_model.pkl')
print("Client 1 model saved as 'client_1_rf_model.pkl'")

joblib.dump(rf_model_2, 'Sisira Vertical split/client_2_rf_model.pkl')
print("Client 2 model saved as 'client_2_rf_model.pkl'")

joblib.dump(rf_model_3, 'Sisira Vertical split/client_3_rf_model.pkl')
print("Client 3 model saved as 'client_3_rf_model.pkl'")

joblib.dump(rf_model_4, 'Sisira Vertical split/client_4_rf_model.pkl')
print("Client 4 model saved as 'client_4_rf_model.pkl'")

joblib.dump(rf_model_5, 'Sisira Vertical split/client_5_rf_model.pkl')
print("Client 5 model saved as 'client_5_rf_model.pkl'")


# In[80]:


import joblib

# Load the saved Random Forest models for each client
rf_model_1_loaded = joblib.load('Sisira Vertical split/client_1_rf_model.pkl')
print("Client 1 model loaded successfully.")

rf_model_2_loaded = joblib.load('Sisira Vertical split/client_2_rf_model.pkl')
print("Client 2 model loaded successfully.")

rf_model_3_loaded = joblib.load('Sisira Vertical split/client_3_rf_model.pkl')
print("Client 3 model loaded successfully.")

rf_model_4_loaded = joblib.load('Sisira Vertical split/client_4_rf_model.pkl')
print("Client 4 model loaded successfully.")

rf_model_5_loaded = joblib.load('Sisira Vertical split/client_5_rf_model.pkl')
print("Client 5 model loaded successfully.")


# In[81]:


import joblib
import os

# Define paths for the saved models
model_paths = {
    "Client 1": "Sisira Vertical split/client_1_rf_model.pkl",
    "Client 2": "Sisira Vertical split/client_2_rf_model.pkl",
    "Client 3": "Sisira Vertical split/client_3_rf_model.pkl",
    "Client 4": "Sisira Vertical split/client_4_rf_model.pkl",
    "Client 5": "Sisira Vertical split/client_5_rf_model.pkl",
}

# Dictionary to store loaded models
loaded_models = {}

# Load all models
for client, path in model_paths.items():
    if os.path.exists(path):
        loaded_models[client] = joblib.load(path)
        print(f"{client} model loaded successfully from {path}")
    else:
        print(f"Error: {client} model file not found at {path}")

# Verify the loaded models (optional)
for client, model in loaded_models.items():
    print(f"{client}: {type(model)}")


# In[ ]:




