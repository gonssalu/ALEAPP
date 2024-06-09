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
    "ThreadsAccountDetails": {
        "name": "Threads - Logged-in Account Details", # REVIEW: Should this be "Threads - Account Details"?
        "description": "Extracts the account details of the current logged-in user in Threads",
        "notes": "Requires a logged-in account.", 
        "author": "Gonçalo Paulino {GitHub/@gonssalu}",
        "version": "0.0.1",
        "date": "2024-06-04",
        "category": "Threads",
        "requirements": "N/A",
        "paths": ('*/com.instagram.barcelona/shared_prefs/com.instagram.barcelona_preferences.xml'),
        "function": "get_threads_account_details"
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
from scripts.ilapfuncs import logfunc, tsv, timeline, convert_ts_int_to_utc, convert_utc_human_to_timezone
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

def get_threads_account_details(files_found, report_folder, seeker, wrap_text, time_offset):
    pass

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
        users_headers = ["Timestamp", "Username", "Searched User ID", "Name", "Was Blocked?", "Followed User?", "User Was Following?"] # TODO: Add a link to visist profile with alert box maybege
        for user in users:
            timestamp = user["client_time"]
            user = user["user"]
            last_follow_status = user["last_follow_status"]
            follow_status = user["follow_status"]
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
        report.write_raw_html(RAW_HTML_RECENT_SEARCHES)
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
    
# Convert a timestamp to HTML with a tooltip
def timestamp_to_html(timestamp, date_time_readable):
    return f'<span data-toggle="tooltip" data-placement="right" title="Timestamp: {timestamp}">{date_time_readable}</span>'

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

RAW_HTML_RECENT_SEARCHES = '''
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