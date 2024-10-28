# N7y
import pandas as pd
import re
import joblib  
import os
from sys import argv


if len(argv) != 2:
    print("""

        [...     [..                   
        [. [..   [..[..... [..         
        [.. [..  [..      [.. [..   [..
        [..  [.. [..     [..   [.. [.. 
        [..   [. [..    [..      [...  
        [..    [. ..    [..       [..  
        [..      [..    [..      [..   
                           [..  

        \t Auther: Natneal Amsalu (N7y)\n\n

    """)

    print("python3 detect.py access.log\n")
    exit()

logfile = argv[1]

if not os.path.isfile(logfile):
    print("Log does not Exist : ", logfile)
    exit()
    

try:

    model = joblib.load('model.joblib')
except:
    print("Coudnt find trained model..")
    exit()
try:

    vectorizer = joblib.load('vectorizer.joblib')
except:
    print("Coudnt find vectorizer..")
    exit()

def parse_log(log_path):
    logs = []
    with open(log_path, "r") as file:
        for line in file:
            match = re.search(r'(?P<ip>\d+\.\d+\.\d+\.\d+) - - \[(?P<datetime>.*?)\] "(?P<method>\w+) (?P<request>.*?) HTTP.*?" (?P<status>\d+) (?P<size>\d+)', line)
            user_agent = re.search(r'"User-Agent: (?P<user_agent>.*?)"', line)
            if match:
                request = match.group('request')
                ip = match.group('ip')
                user_agent_str = user_agent.group('user_agent') if user_agent else "00"
                logs.append((ip, request, user_agent_str))
    return pd.DataFrame(logs, columns=['ip', 'request', 'user_agent'])

def extract_features(df):
    request_texts = df['request'].fillna('')
    

    X_text = vectorizer.transform(request_texts).toarray()


    df.loc[:, 'num_special_chars'] = df['request'].apply(lambda x: len(re.findall(r'[<>{}\'\";]', str(x))))
    df.loc[:, 'num_sql_keywords'] = df['request'].apply(lambda x: len(re.findall(r'\b(select|union|drop|insert|update)\b', str(x), re.IGNORECASE)))
    df.loc[:, 'num_encoded_chars'] = df['request'].apply(lambda x: len(re.findall(r'%[0-9a-fA-F]{2}', str(x))))


    X = pd.concat([pd.DataFrame(X_text), df[['num_special_chars', 'num_sql_keywords', 'num_encoded_chars']]], axis=1)
    

    X.columns = X.columns.astype(str)
    
    return X


log_path = logfile
new_df = parse_log(log_path)
X_new = extract_features(new_df[['request']])  


predictions = model.predict(X_new)
new_df['is_threat'] = predictions

threats = new_df[new_df['is_threat'] == 1]
if not threats.empty:
    os.system("clear");
    print("""

        [...     [..                   
        [. [..   [..[..... [..         
        [.. [..  [..      [.. [..   [..
        [..  [.. [..     [..   [.. [.. 
        [..   [. [..    [..      [...  
        [..    [. ..    [..       [..  
        [..      [..    [..      [..   
                           [..  

        \t Auther: Natneal Amsalu (N7y)\n\n

    """)
    print("Threats detected:\n\n")
    for _, row in threats.iterrows():
        if row['request'] == "/favicon.ico":
            continue
        print(f"From IP: {row['ip']}, Request: {row['request']}, ")
    # print(threats[['ip', 'request', 'user_agent', 'is_threat']])
    print("\n")
else:
    print("No threats detected")


