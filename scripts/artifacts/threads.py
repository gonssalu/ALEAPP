# Threads (com.instagram.barcelona)
# Author:  Gonçalo Paulino (gonssalu@proton.me)
# Version: 0.0.3
# 
# Tested with the following versions:
# 2024-06-04: Android 12, App: 332.0.0.34.109

# Requirements:  N/A


# TODO: Add link to notes
__artifacts_v2__ = {
    "ThreadsAccountHistory": {
        "name": "Threads - Account History",
        "description": "Extracts information about the accounts that have been used in Threads",
        "notes": "Will include accounts the user has logged out of. Parses the ID and username of each account; extracts the timestamps of the last activity by each account on the device.", 
        "author": "Gonçalo Paulino {GitHub/@gonssalu}",
        "version": "1.0.0",
        "date": "2024-06-05",
        "category": "Threads",
        "requirements": "N/A",
        "paths": ('*/com.instagram.barcelona/shared_prefs/autobackupprefs.xml',
                  '*/com.instagram.barcelona/shared_prefs/*_last_active_timestamp.xml'),
        "function": "get_threads_account_history",
    },
    "ThreadsLoggedInAccountDetails": {
        "name": "Threads - Logged-in Account",
        "description": "Extracts the account details of the current logged-in account in Threads",
        "notes": "Requires a logged-in account.", 
        "author": "Gonçalo Paulino {GitHub/@gonssalu}",
        "version": "1.0.0",
        "date": "2024-06-10",
        "category": "Threads",
        "requirements": "N/A",
        "paths": ('*/com.instagram.barcelona/shared_prefs/com.instagram.barcelona_preferences.xml'),
        "function": "get_threads_account_details"
    },
    "ThreadsTimestampMetrics": {
        "name": "Threads - Timestamp Metrics",
        "description": "Extracts timestamps from app usage metrics in Threads. This includes the last time the app was opened, the last time it was in the background, the time spent in the foreground and open/close timestamps by account.",
        "notes": "", 
        "author": "Gonçalo Paulino {GitHub/@gonssalu}",
        "version": "1.1.0",
        "date": "2024-06-10",
        "category": "Threads",
        "requirements": "N/A",
        "paths": ('*/com.instagram.barcelona/shared_prefs/com.instagram.barcelona_preferences.xml', '*/com.instagram.barcelona/databases/time_in_app_*.db'),
        "function": "get_threads_timestamp_metrics"
    },
    "ThreadsRecentSearches": {
        "name": "Threads - Recent Searches",
        "description": "Extract the user's recent keyword and user searches from the logged-in account in Threads",
        "notes": "Requires a logged-in account.", 
        "author": "Gonçalo Paulino {GitHub/@gonssalu}",
        "version": "1.0.0'",
        "date": "2024-06-06",
        "category": "Threads",
        "requirements": "N/A",
        "paths": ('*/com.instagram.barcelona/shared_prefs/*_USER_PREFERENCES.xml'),
        "function": "get_threads_recent_searches"
    },
    "ThreadsLoggedIPAddresses": {
        "name": "Threads - IP Addresses",
        "description": "Extracts the IP addresses that were logged in Threads' HTTP request cache",
        "notes": "Includes the associated user ID (when applicable) and the date of the request",
        "author": "Gonçalo Paulino {GitHub/@gonssalu}",
        "version": "1.0.0",
        "date": "2024-06-08",
        "category": "Threads",
        "requirements": "N/A",
        "paths": ('*/com.instagram.barcelona/cache/http_responses/*-resp_info_gzip.clean'),
        "function": "get_threads_logged_ip_addrs"
    }
}


from scripts.artifact_report import ArtifactHtmlReport
from scripts.ilapfuncs import logfunc, tsv, timeline, convert_ts_int_to_utc, convert_utc_human_to_timezone, open_sqlite_db_readonly
import xml.etree.ElementTree as ElementTree
import html, json, gzip
from datetime import datetime
#from open_sqlite_db_readonly

def get_threads_account_history(files_found, report_folder, seeker, wrap_text, time_offset):
    
    user_map = []
    uid_timestamps = [];
    for file_path in files_found:
        file_found = str(file_path)
        dir_sep = get_dir_separator(file_found)
        file_name = file_found.rsplit(dir_sep, 1)[-1]
        
        xmlTree = ElementTree.parse(file_found)
        root = xmlTree.getroot()

        # Process autobackupprefs.xml
        if "autobackupprefs.xml" in file_found:
            logfunc("Parsing autobackupprefs.xml...")
            for child in root:
                if child.attrib['name'] == "cloud_account_user_map":
                    try:
                        user_map = json.loads(html.unescape(child.text))["cloud_accounts_list"]
                        user_map_len = len(user_map)
                        logfunc(f'Found and extracted {user_map_len} user(s)')
                    except:
                        logfunc("Error parsing cloud_account_user_map JSON")
        else:
            # Process *_last_active_timestamp.xml
            logfunc(f'Parsing {file_name}...')
            uid = file_name.split('_')[0]
            open_timestamp = None
            for child in root:
                if child.attrib['name'] == "last_app_foreground_timestamp":
                    open_timestamp = child.attrib['value']
                    break
            # If a timestamp was found, add it to the list
            if open_timestamp:
                date_time_readable = convert_ts_int_to_date(float(open_timestamp) / 1000.0, time_offset).strftime(TIMESTAMP_FORMAT)
                uid_timestamps.append({"uid": uid, "timestamp": open_timestamp, "date_time": date_time_readable, "timestamp_html": timestamp_to_html(open_timestamp, date_time_readable)})

    # If we found any data, write it to the report
    if user_map or uid_timestamps:
        processed_uids = []
        data_rows = []
        tsv_rows = []
        
        # Correlate the user data with the timestamps
        for user in user_map:
            uid = user['user_id']
            username = user['username']
            last_active = None
            for uid_timestamp in uid_timestamps:
                if uid_timestamp['uid'] == uid:
                    last_active_html = uid_timestamp['timestamp_html']
                    last_active = uid_timestamp['timestamp']
                    date_time_readable = uid_timestamp['date_time']
                    processed_uids.append(uid)
                    break
            data_rows.append((uid, username, ("N/A" if last_active_html==None else last_active_html)))
            tsv_rows.append((uid, username, ("N/A" if last_active==None else last_active)))
            logfunc(f'Found user: {username} ({uid}) - ' + (f'Last active: {date_time_readable} ({last_active})' if last_active else "No activity timestamp found"))
        
        for ut in uid_timestamps:
            if ut['uid'] not in processed_uids:
                data_rows.append((ut['uid'], "N/A", ut['timestamp_html']))
                tsv_rows.append((ut['uid'], "N/A", ut['timestamp']))
                logfunc(f'Found account ID: {ut["uid"]} - Last active: {ut["date_time"]} ({ut["timestamp"]})')
        
        # Write the data to the report
        headers = ["Account ID", "Username", "Last Active"]
        
        artifact_name = 'Account History'
        report_name = 'ThreadsAccountHistory'
        category = 'Threads'
        description = "This artifact provides a list of accounts that have been used in Threads, including the last activity timestamp for each account.<br/>Includes accounts the user has logged out of."
        source_file = str(files_found[0].split(dir_sep)[0])
        
        report = init_report(artifact_name, category, description, report_folder)
        
        report.write_minor_header("Results")
        report.write_artifact_data_table(headers, data_rows, source_file, html_escape=False, write_location=False)
        
        print_sources_to_report(report, files_found)
        report.end_artifact_report()
        
        # Generate a TSV file
        tsv(report_folder, headers, tsv_rows, report_name)

    else:
        logfunc('No user history data found in Threads artifacts')

def process_preferences_xml(file_path, process_acc_details):
    acc_details = {};
    acc_details["file_path"] = clean_path(file_path);
    file_found = str(file_path)
    
    if not process_acc_details:
        acc_details["timestamps"] = {}
    
    xmlTree = ElementTree.parse(file_found)
    root = xmlTree.getroot()

    # Process com.instagram.barcelona_preferences.xml
    for child in root:
        if not process_acc_details:
            if child.attrib['name'] == "last_app_start_timestamp":
                acc_details["timestamps"]["last_app_start"] = child.attrib['value']
            if child.attrib['name'] == "all_start_latest_background_time":
                acc_details["timestamps"]["background_app_start"] = child.attrib['value']
            if child.attrib['name'] == "foreground_timespent_since_upgrade":
                acc_details["timestamps"]["foreground_timespent"] = child.attrib['value']
        else:
            if child.attrib['name'] == "user_access_map":
                try:
                    user_access_map = json.loads(html.unescape(child.text))[0]
                    acc_details["user_map"] = user_access_map["user_info"]
                    
                    acc_details["user_map_ts"] = user_access_map["time_accessed"]
                    break
                except:
                    logfunc("Error parsing user_access_map JSON")
                        
    return acc_details

def get_threads_account_details(files_found, report_folder, seeker, wrap_text, time_offset):
    
    acc_details = process_preferences_xml(files_found[0], True)
    
    if not "user_map" in acc_details:
        logfunc('No logged-in account details found in Threads artifacts')
        return
    
    # Initialise the report
    artifact_name = 'Logged-in Account'
    report_name = 'ThreadsLoggedInAccountDetails'
    category = 'Threads'
    description = "Extracts information about the logged-in user's account in Threads."
    
    report = init_report(artifact_name, category, description, report_folder)
    
    # Extract data from the JSON
    timestamp = acc_details["user_map_ts"]
    date_time_readable = convert_ts_int_to_date(int(timestamp)/1000.0, time_offset).strftime(TIMESTAMP_FORMAT)
    account_id = acc_details["user_map"]["id"]
    username = acc_details["user_map"]["username"]
    name = acc_details["user_map"]["full_name"]
    privacy = convert_status_to_readable("Privacy", acc_details["user_map"]["privacy_status"])
    follower_count = "N/A" if "follower_count" not in acc_details["user_map"] else acc_details["user_map"]["follower_count"]
    following_count = "N/A" if "following_count" not in acc_details["user_map"] else acc_details["user_map"]["following_count"]
    file_path = acc_details["file_path"]
    user_json = json.dumps(acc_details["user_map"], indent=4, sort_keys=True)
    
    # Log extracted data
    logfunc(f'Found account ID: {account_id}')
    logfunc(f'Username: {username}')
    logfunc(f'Name: {name}')
    logfunc(f'Privacy: {privacy}')
    logfunc(f'Follower Count: {follower_count}')
    logfunc(f'Following Count: {following_count}')
    logfunc(f'Timestamp: {date_time_readable} ({timestamp})')
    
    # Write to the report
    raw_html = RAW_HTML_ACCOUNT_DETAILS.split("%USER_JSON%")
    populated_html_1 = raw_html[0].replace("%TIMESTAMP%", timestamp_to_html(timestamp, date_time_readable)).replace("%ACC_ID%", account_id).replace("%USERNAME%", username).replace("%NAME%", name).replace("%PRIVACY%", privacy).replace("%SOURCE_FILE%", file_path)
    
    if follower_count != "N/A" or following_count != "N/A":
        populated_html_1 = populated_html_1.replace("%FOLLOWER_INFO%", RAW_HTML_AD_FOLLOWER.replace("%FOLLOWER_COUNT%", str(follower_count)).replace("%FOLLOWING_COUNT%", str(following_count)))
    
    report.write_raw_html(populated_html_1)
    write_json_block_without_heading(report, user_json)
    report.write_raw_html(raw_html[1])

    report.end_artifact_report()
    
    # Generate a TSV file
    headers = ["Artifact Timestamp", "Account ID", "Username", "Name", "Privacy", "Follower Count", "Following Count"]
    tsv_rows = [[timestamp, account_id, username, name, privacy, follower_count, following_count]]
    tsv(report_folder, headers, tsv_rows, report_name, file_path)

def get_threads_timestamp_metrics(files_found, report_folder, seeker, wrap_text, time_offset):
    acc_details = {}
    usr_timestamps = []
    usr_timestamps_sources = []
    
    for file_found in files_found:
        file_found_str = str(file_found)
        dir_sep = get_dir_separator(file_found_str)
        file_name = file_found_str.rsplit(dir_sep, 1)[-1]
        
        logfunc(f'Parsing {file_name}...')
        if("com.instagram.barcelona_preferences.xml" == file_name):
          acc_details = process_preferences_xml(files_found[0], False)
        else:
          uid = file_name.rsplit('_', 1)[-1].split('.')[0]
          db = open_sqlite_db_readonly(file_found)

          cursor = db.cursor()
          cursor.execute('SELECT start_walltime, end_walltime FROM intervals WHERE start_event = 1 ORDER BY seq_num DESC')

          all_rows = cursor.fetchall()
          entries_retrieved = len(all_rows)
          if entries_retrieved > 0:
              logfunc(f'Found {entries_retrieved} timestamp(s) for user ID: {uid}')
              for row in all_rows:
                  opened_readable = convert_ts_int_to_date(int(row[0]), time_offset).strftime(TIMESTAMP_FORMAT)
                  closed_readable = convert_ts_int_to_date(int(row[1]), time_offset).strftime(TIMESTAMP_FORMAT)
                  usr_timestamps.append({"user_id": uid, "opened": row[0], "closed": row[1], "opened_readable": opened_readable, "closed_readable": closed_readable, "source_file": clean_path(file_found_str)})
                  usr_timestamps_sources.append(clean_path(file_found_str))
                  logfunc(f'App Opened: {opened_readable} ({row[0]}) - App Closed: {closed_readable} ({row[1]})')
    
    has_general_timestamps = "timestamps" in acc_details and acc_details["timestamps"]
    if not has_general_timestamps and not usr_timestamps:
        logfunc('No timestamp metrics were found')
        
    # Initialise the report
    artifact_name = 'Timestamp Metrics'
    report_name = 'ThreadsTimestampMetrics'
    category = 'Threads'
    description = "Extracts timestamps from app usage metrics in Threads.<br/>This includes the last time the app was opened, the last time it was in the background, the time spent in the foreground and open/close timestamps by account."
    
    report = init_report(artifact_name, category, description, report_folder)
    
    if has_general_timestamps:
      # Extract data from the JSON
      foreground_app_start = acc_details["timestamps"]["last_app_start"]
      background_app_start = acc_details["timestamps"]["background_app_start"]
      foreground_time_spent = acc_details["timestamps"]["foreground_timespent"]
      file_path = acc_details["file_path"]
      
      foreground_readable = convert_ts_int_to_date(int(foreground_app_start)/1000.0, time_offset).strftime(TIMESTAMP_FORMAT)
      background_readable = convert_ts_int_to_date(int(background_app_start)/1000.0, time_offset).strftime(TIMESTAMP_FORMAT)
      fts_readable = format_milliseconds(int(foreground_time_spent))
      
      # Log extracted data
      logfunc(f'Last Foreground Start: {foreground_readable} ({foreground_app_start})')
      logfunc(f'Last Background Start: {background_readable} ({background_app_start})')
      logfunc(f'Time Spent in Foreground: {fts_readable} ({foreground_time_spent} milliseconds)')
      
      # Write to the report
      raw_html = RAW_HTML_TIMESTAMP_METRICS.replace("%LAST_APP_START%", timestamp_to_html(foreground_app_start, foreground_readable)).replace("%BACKGROUND_APP_START%", timestamp_to_html(background_app_start, background_readable)).replace("%FOREGROUND_TIME_SPENT%", f'<span data-toggle="tooltip" data-placement="right" title="{foreground_time_spent} milliseconds">{fts_readable}</span>').replace("%SOURCE_FILE%", file_path)
      report.write_raw_html(raw_html)
      
      #Generate a TSV file
      headers = ["Last Foreground Start", "Last Background Start", "Time Spent in Foreground"]
      tsv_rows = [[foreground_app_start, background_app_start, foreground_time_spent]]
      tsv(report_folder, headers, tsv_rows, f'{report_name}_GeneralUsage', file_path)
      
    if usr_timestamps:
      # Write the user timestamps to the report
      report.write_raw_html('<hr class="bg-light my-4"/>')
      report.write_minor_header("App Usage Timestamps by User")
      
      # Sort the timestamps by the opened timestamp
      usr_timestamps = sorted(usr_timestamps, key=lambda x: x["opened"])
      
      headers = ["User ID", "App Opened At", "App Closed At"]
      data_rows = []
      for usr_timestamp in usr_timestamps:
          opened_tmstmp = usr_timestamp["opened"]
          closed_tmstmp = usr_timestamp["closed"]
          opened_readable = usr_timestamp["opened_readable"]
          closed_readable = usr_timestamp["closed_readable"]
          data_rows.append((usr_timestamp["user_id"], timestamp_to_html(opened_tmstmp, opened_readable), timestamp_to_html(closed_tmstmp, closed_readable)))
          
          # Generate a TSV file
          tsv_rows.append((usr_timestamp["user_id"], opened_tmstmp, closed_tmstmp, usr_timestamp["source_file"]))
      
      report.write_artifact_data_table(headers, data_rows, usr_timestamps[0]["source_file"], html_escape=False, write_location=False)
      
      print_sources_to_report(report, usr_timestamps_sources, True)
      # Generate a TSV file
      headers.append("source file")
      tsv(report_folder, headers, tsv_rows, f'{report_name}_UserUsage')
    
    report.end_artifact_report()
    

def get_threads_recent_searches(files_found, report_folder, seeker, wrap_text, time_offset):
    
    keywords = []
    users = []
    found = False
    file_found = None
    
    # Process *_USER_PREFERENCES.xml files until something is found
    for file_path in files_found:
        file_found = str(file_path)
        dir_sep = get_dir_separator(file_found)
        
        xmlTree = ElementTree.parse(file_found)
        root = xmlTree.getroot()

        file_name = file_found.rsplit(dir_sep, 1)[-1]
        logfunc(f'Parsing {file_name}...')
        
        for child in root:
            if child.attrib['name'] == "recent_keyword_searches_with_ts":
                try:
                    keywords = json.loads(html.unescape(child.text))["keywords"]
                    keywords_len = len(keywords)
                    found = True
                    logfunc(f'Found and extracted {keywords_len} keyword(s)')
                except:
                    logfunc("Error parsing recent_keyword_searches_with_ts JSON")
            if child.attrib['name'] == "recent_user_searches_with_ts":
                try:
                    users = json.loads(html.unescape(child.text))["users"]
                    users_len = len(users)
                    found = True
                    logfunc(f'Found and extracted {users_len} user(s)')
                except:
                    logfunc("Error parsing recent_user_searches_with_ts JSON")
        # If a file with recent searches was found, stop looking because only the logged-in account can have recent searches data
        if found:
            break
    
    report_name = 'ThreadsRecentSearches'
    category = 'Threads'
    source_file = clean_path(file_found)
    
    # If no data was found skip the reports
    if not keywords and not users:
        logfunc('No recent search data found in Threads artifacts')
        return
    
    # If any keywords were found, write them to the report
    if keywords:
        keyword_data_rows = []
        keyword_tsv_rows = []
        keyword_headers = ["Timestamp", "Searched Keyword"]
        for keyword in keywords:
            timestamp = keyword["client_time"]
            keyword = keyword["keyword"]
            date_time_readable = convert_ts_int_to_date(int(timestamp), time_offset).strftime(TIMESTAMP_FORMAT)
            keyword_data_rows.append((timestamp_to_html(timestamp, date_time_readable), keyword["name"]))
            keyword_tsv_rows.append((timestamp, keyword["name"]))
            logfunc(f'Found keyword: {keyword["name"]} - Timestamp: {date_time_readable} ({timestamp})')
       
       
       # Initialise the keyword searches report
        artifact_name = 'Recent Searches - Keywords'
        description = "This artifact provides a list of recent keyword searches from the logged-in account in Threads."
        report = init_searches_report(artifact_name, category, description, report_folder, file_name, source_file)
        
        # Write the keyword data to the report
        report.write_minor_header("Keyword Searches")
        report.write_artifact_data_table(keyword_headers, keyword_data_rows, source_file, html_escape=False, write_location=False)
        if users:
            report.write_raw_html('<hr class="bg-light my-4"/>')
        
        report.end_artifact_report()
        
        # Generate a TSV file
        tsv(report_folder, keyword_headers, keyword_tsv_rows, f'{report_name}_Keywords', source_file)
      
    # If any users were found, write them to the report  
    if users:
        users_data_rows = []
        users_tsv_rows = []
        users_headers = ["Timestamp", "Username", "Searched User ID", "Name", "Was Blocked?", "Followed User?", "User Was Following?"]
        for user in users:
            timestamp = user["client_time"]
            user = user["user"]
            last_follow_status = convert_status_to_readable("Follow", user["last_follow_status"])
            follow_status = convert_status_to_readable("Follow", user["follow_status"])
            date_time_readable = convert_ts_int_to_date(int(timestamp), time_offset).strftime(TIMESTAMP_FORMAT)
            users_data_rows.append((timestamp_to_html(timestamp, date_time_readable), user["username"], user["id"], user["full_name"], bool_to_emoji(user["blocking"]), f'{last_follow_status} -> {follow_status}', bool_to_emoji(user["is_following_current_user"])))
            users_tsv_rows.append((timestamp, user["username"], user["id"], user["full_name"], user["blocking"], f'{last_follow_status} -> {follow_status}', user["is_following_current_user"]))
            logfunc(f'Found user: {user["username"]} ({user["id"]}) - Timestamp: {date_time_readable} ({timestamp}) - Was Blocked?: {user["blocking"]} - Followed User?: ' + f'{last_follow_status} -> {follow_status}' + f' - User Was Following?: {user["is_following_current_user"]}')
        
       
       # Initialise the user searches report
        artifact_name = 'Recent Searches - Users'
        description = "This artifact provides a list of recent user searches from the logged-in account in Threads."
        report = init_searches_report(artifact_name, category, description, report_folder, file_name, source_file)
        
        # Write the user searches data to the report
        report.write_minor_header("User Searches")
        report.write_lead_text("For a given row, the extracted data was true on the displayed timestamp.")
        report.write_raw_html(RAW_HTML_RECENT_USER_SEARCHES)
        report.write_artifact_data_table(users_headers, users_data_rows, source_file, html_escape=False, write_location=False)
        
        report.end_artifact_report()
        
        # Generate a TSV file
        tsv(report_folder, users_headers, users_tsv_rows, f'{report_name}_Users', source_file)

def get_threads_logged_ip_addrs(files_found, report_folder, seeker, wrap_text, time_offset):
    
    ip_addresses = []
    ip_addresses_tsv = []
    files_used = []
    
    # Process all *_resp_info_gzip.clean files
    for file_path in files_found:
        file_found = str(file_path)
        
        dir_sep = get_dir_separator(file_found)
        file_name = file_found.rsplit(dir_sep, 1)[-1]
        
        logfunc(f'Parsing {file_name}...')
        
        # Open the gzip files
        try:
            with gzip.open(file_path, 'rt') as gzip_file:
                content = gzip_file.read()
                resp_info = json.loads(content)
                user_id = None
                ip_addr = None
                date = None
                for header in resp_info["headers"]:
                    if header["name"] == "Date":
                        date = convert_ts_int_to_date(datetime.strptime(header["value"], "%a, %d %b %Y %H:%M:%S %Z").timestamp(), time_offset).strftime(TIMESTAMP_FORMAT)
                    if header["name"] == "ig-set-ig-u-ds-user-id":
                        user_id = header["value"]
                    if header["name"] == "X-FB-Client-IP-Forwarded":
                        ip_addr = header["value"]
                    if user_id and ip_addr and date:
                        break
                if not ip_addr:
                    logfunc('No IP address found')
                    continue
                fixed_path = clean_path(file_path)
                ip_addresses.append((user_id if user_id else "N/A", ip_addr_to_html(ip_addr), date if date else "Unknown"))
                ip_addresses_tsv.append((user_id if user_id else "N/A", ip_addr, date if date else "Unknown", fixed_path))
                files_used.append(fixed_path)
                logfunc(f'Found IP address: {ip_addr} - Date: {date} - User ID: {user_id}')
        except Exception as e:
            logfunc(f'Error parsing gzip file: {type(e).__name__}')
            logfunc(f'Error message: {str(e)}')
    
    if not ip_addresses:
        logfunc('No IP addresses found in Threads artifacts')
        return
    
    # Initialise the IP addresses report
    report_name = 'ThreadsIPAddresses'
    category = 'Threads'
    artifact_name = 'IP Addresses'
    description = "This artifact provides a list of IP addresses that were logged in Threads' HTTP request cache, including the associated user ID (when applicable) and the date of the request."
    headers = ["User ID", "IP Address", "Date"]
    
    report = init_report(artifact_name, category, description, report_folder)
    
    # Write the IP address data to the report
    report.write_minor_header("Results")
    report.write_artifact_data_table(headers, ip_addresses, files_used[0].split(dir_sep)[0], html_escape=False, write_location=False)
    
    print_sources_to_report(report, files_used)
        
    report.end_artifact_report()
    
    # Generate a TSV file
    headers.append("source file")
    tsv(report_folder, headers, ip_addresses_tsv, report_name)
    

# Get the directory separator based on the file path
def get_dir_separator(file_path):
    if '\\' in file_path:
        return '\\'
    else:
        return '/'
    
# Convert a timestamp int to a datetime object in the case's timezone
def convert_ts_int_to_date(ts, time_offset):
    return convert_utc_human_to_timezone(convert_ts_int_to_utc(ts), time_offset)

# Convert a status to a readable format
def convert_status_to_readable(prefix: str,  status: str):
    full_prefix = f'{prefix}Status'
    return status.replace(full_prefix, "") if full_prefix in status else status

# Convert a timestamp to HTML with a tooltip
def timestamp_to_html(timestamp, date_time_readable):
    return f'<span data-toggle="tooltip" data-placement="right" title="Timestamp: {timestamp}">{date_time_readable}</span>'

def format_milliseconds(milliseconds):
    days = milliseconds // 86400000
    milliseconds %= 86400000
    hours = milliseconds // 3600000
    milliseconds %= 3600000
    minutes = milliseconds // 60000
    milliseconds %= 60000
    seconds = milliseconds // 1000
    milliseconds %= 1000

    parts = []
    if days > 0:
        parts.append(f"{days} day{'s' if days != 1 else ''}")
    if hours > 0:
        parts.append(f"{hours} hour{'s' if hours != 1 else ''}")
    if minutes > 0:
        parts.append(f"{minutes} minute{'s' if minutes != 1 else ''}")
    if seconds > 0:
        parts.append(f"{seconds} second{'s' if seconds != 1 else ''}")
    if milliseconds > 0:
        parts.append(f"{milliseconds} millisecond{'s' if milliseconds != 1 else ''}")

    return ' '.join(parts)

# Convert a boolean to an HTML emoji
def bool_to_emoji(value):
    no_emoji = "&#10006; (No)"
    yes_emoji = "&#9989; (Yes)"
    return f'<span data-toggle="tooltip" data-placement="right" title="{value}">{yes_emoji if bool(value) else no_emoji}</span>'

# Convert an IP address to HTML with a tooltip
def ip_addr_to_html(ip_addr):
    return f'<a href="https://whatismyipaddress.com/ip/{ip_addr}" target="_blank" class="text-primary" data-toggle="tooltip" data-placement="right" title="Click to open IP lookup in new tab">{ip_addr}</a>'

# Remove unneeded characters from the file path
def clean_path(path):
    return path[4:] if path.startswith('\\\\?\\') else path

# Print sources to the report
def print_sources_to_report(report, files_found, is_after_results=False):
    if isinstance(files_found, str):
        files_found = [files_found]
    
    if not is_after_results:
        report.write_raw_html('<hr class="bg-light my-4"/>')
    
    report.write_minor_header("Source" + ("s" if len(files_found) > 1 else ""))
    report.write_raw_html(f'<ul class="list-group{"" if is_after_results else " mb-4"}">')    
    for file_found in files_found:
        file_path = clean_path(file_found)
        report.write_raw_html(f'<li class="list-group-item bg-white"><code>{str((file_path))}</code></li>')
        
    report.write_raw_html('</ul><hr class="bg-light my-4"/>' if is_after_results else '</ul>')

def write_json_block_without_heading(report: ArtifactHtmlReport, json_data):
    report.write_raw_html(f'<div class="jsonBlock mt-4">')
    report.write_raw_html(f'<pre><code id="jsonCode">{json_data}</code></pre>')
    report.write_raw_html('</div>')
    report.write_raw_html('<script>hljs.highlightAll();</script>')

# Initialise the report (Shared code for all artifacts)
def init_report(artifact_name, category, description, report_folder) -> ArtifactHtmlReport:
    report = ArtifactHtmlReport(f'{category} - {artifact_name}', category)
    report.start_artifact_report(report_folder, f'{category} - {artifact_name}', description)
    report.add_script()
    return report

def init_searches_report(artifact_name, category, description, report_folder, file_name, source_file) -> ArtifactHtmlReport:
    report = init_report(artifact_name, category, description, report_folder)
    report.write_lead_text("Logged-in account ID: " + file_name.split('_')[0])
    print_sources_to_report(report, source_file, True)
    return report

TIMESTAMP_FORMAT = "%Y-%m-%d %H:%M:%S %Z" # "%d %b %Y %H:%M:%S %Z"

RAW_HTML_RECENT_USER_SEARCHES = '''
<div class="row mb-4">
  <div class="col-sm-4">
    <div class="card bg-white h-100 d-flex flex-column" style="box-shadow: 0 2px 5px 0 rgba(0,0,0,0.16),0 2px 10px 0 rgba(0,0,0,0.12)">
      <div class="card-body" style="overflow-y: hidden; height: auto">
        <h5 class="card-title">Was Blocked?</h5>
        <p class="card-text">Was the searched user blocked by the logged-in account?</p>
      </div>
    </div>
  </div>
  <div class="col-sm-4">
    <div class="card bg-white h-100 d-flex flex-column" style="box-shadow: 0 2px 5px 0 rgba(0,0,0,0.16),0 2px 10px 0 rgba(0,0,0,0.12)">
      <div class="card-body" style="overflow-y: hidden; height: auto">
        <h5 class="card-title">Followed User?</h5>
        <p class="card-text">Was the logged-in account following the user?<br/>The first value answers this question when the searched user popped up in the search results.<br/>The second value answers this question when the searched user's profile was clicked.</p>
      </div>
    </div>
  </div>
  <div class="col-sm-4">
    <div class="card bg-white h-100 d-flex flex-column" style="box-shadow: 0 2px 5px 0 rgba(0,0,0,0.16),0 2px 10px 0 rgba(0,0,0,0.12)">
      <div class="card-body" style="overflow-y: hidden; height: auto">
        <h5 class="card-title">User Was Following?</h5>
        <p class="card-text">Was the searched user following the logged-in account?</p>
      </div>
    </div>
  </div>
</div>
'''

RAW_HTML_ACCOUNT_DETAILS = '''
<div class="card bg-white" style="padding: 20px">
  <h2 class="card-title">User Information</h2>

  <ul class="nav nav-tabs" id="threadsAccTab" role="tablist">
    <li class="nav-item waves-effect waves-light">
      <a
        class="nav-link active"
        id="accDetails-tab"
        data-toggle="tab"
        href="#accDetails"
        role="tab"
        aria-controls="accDetails"
        aria-selected="true"
        >Details</a
      >
    </li>
    <li class="nav-item waves-effect waves-light">
      <a
        class="nav-link"
        id="userFullJson-list-tab"
        data-toggle="tab"
        href="#userFullJson"
        role="tab"
        aria-controls="userFullJson"
        aria-selected="false"
        >Full JSON</a
      >
    </li>
  </ul>
  <div class="tab-content" id="threadsAccTabContent">
    <div
      class="tab-pane fade active show"
      id="accDetails"
      role="tabpanel"
      aria-labelledby="accDetails-tab"
    >
      <br />
      <div class="table-responsive">
        <table class="table table-bordered table-hover table-sm" width="70%">
          <tbody>
            <tr>
              <th>Source File</th>
              <td><code>%SOURCE_FILE%</code></td>
            </tr>
            <tr>
              <th
                data-toggle="tooltip"
                data-placement="right"
                title="The last time this artifact's information was updated"
                style="text-decoration: underline dotted"
              >
                Artifact Date
              </th>
              <td>%TIMESTAMP%</td>
            </tr>
            <tr>
              <th>ID</th>
              <td>%ACC_ID%</td>
            </tr>
            <tr>
              <th>Username</th>
              <td>%USERNAME%</td>
            </tr>
            <tr>
              <th>Name</th>
              <td>%NAME%</td>
            </tr>
            <tr>
              <th
                data-toggle="tooltip"
                data-placement="right"
                title="Is the account public or private?"
                style="text-decoration: underline dotted"
              >
                Account Privacy
              </th>
              <td>%PRIVACY%</td>
            </tr>
            %FOLLOWER_INFO%
          </tbody>
        </table>
      </div>

      <p class="note note-primary mb-4">
        <span class="font-weight-bold">Artifact Date</span> represents the last time this artifact's information was
        updated.
      </p>
    </div>
    <div
      class="tab-pane fade"
      id="userFullJson"
      role="tabpanel"
      aria-labelledby="userFullJson-tab"
    >
      %USER_JSON%
    </div>
  </div>
</div>
'''

RAW_HTML_AD_FOLLOWER = '''
<tr>
  <th
    data-toggle="tooltip"
    data-placement="right"
    title="If 'N/A', no data was found"
    style="text-decoration: underline dotted"
  >
    Follower Count
  </th>
  <td>%FOLLOWER_COUNT%</td>
</tr>
<tr>
  <th
    data-toggle="tooltip"
    data-placement="right"
    title="If 'N/A', no data was found"
    style="text-decoration: underline dotted"
  >
    Following Count
  </th>
  <td>%FOLLOWING_COUNT%</td>
</tr>
'''

RAW_HTML_TIMESTAMP_METRICS = '''
<div class="card bg-white" style="padding: 20px">
  <h3 class="card-title h3">Overall Timestamps</h3>
  <div class="table-responsive">
    <table class="table table-bordered table-hover table-sm" width="70%">
      <tbody>
        <tr>
          <th>Source File</th>
          <td><code>%SOURCE_FILE%</code></td>
        </tr>
        <tr>
          <th>Last Foreground Start</th>
          <td>%LAST_APP_START%</td>
        </tr>
        <tr>
          <th>Last Background Start</th>
          <td>%BACKGROUND_APP_START%</td>
        </tr>
        <tr>
          <th
            data-toggle="tooltip"
            data-placement="right"
            title="The number of milliseconds Threads has spent in the foreground since the last update"
            style="text-decoration: underline dotted"
          >
            Time Spent in Foreground
          </th>
          <td>%FOREGROUND_TIME_SPENT%</td>
        </tr>
      </tbody>
    </table>
  </div>
  <p class="note note-primary mb-4">
    <span class="font-weight-bold">Time Spent in Foreground</span> represents
    the number of milliseconds Threads has spent in the foreground since the last
    update.
  </p>
</div>
'''