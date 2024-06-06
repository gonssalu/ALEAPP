# Threads (com.instagram.barcelona)
# Author:  Gonçalo Paulino (gonssalu@proton.me)
# Version: 0.0.1
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
        "date": "2024-06-04",
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
        "description": "Extract the user's recent searches in the logged-in account in Threads",
        "notes": "Requires a logged-in account. More information on LINK", 
        "author": "Gonçalo Paulino {GitHub/@gonssalu}",
        "version": "0.0.1",
        "date": "2024-06-04",
        "category": "Threads",
        "requirements": "N/A",
        "paths": ('*/com.instagram.barcelona/shared_prefs/*_USER_PREFERENCES.xml'),
        "function": "get_threads_recent_searches"
    },
    "ThreadsLoggedIPAddresses": {
        "name": "IP Addresses - Threads",
        "description": "Extracts the IP addresses that were logged by Threads",
        "notes": "More information on LINK", 
        "author": "Gonçalo Paulino {GitHub/@gonssalu}",
        "version": "0.0.1",
        "date": "2024-06-04",
        "category": "Network",
        "requirements": "N/A",
        "paths": ('*/com.instagram.barcelona/cache/http_responses/*-resp_info_gzip.clean'),
        "function": "get_threads_logged_ip_addrs"
    }
}


from scripts.artifact_report import ArtifactHtmlReport
from scripts.ilapfuncs import logfunc, tsv, timeline, convert_ts_int_to_utc
import xml.etree.ElementTree as ElementTree
import html, json
#from open_sqlite_db_readonly

# Get the directory separator based on the file path
def get_dir_separator(file_path):
    if '\\' in file_path:
        return '\\'
    else:
        return '/'

def get_threads_account_history(files_found, report_folder, seeker, wrap_text, time_offset):
    
    user_map = []
    uid_timestamps = [];
    for file_path in files_found:
        file_found = str(file_path)
        dir_sep = get_dir_separator(file_found)
        file_name = file_found.rsplit(dir_sep, -1)[-1]
        
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
                date_time_readable = convert_ts_int_to_utc(float(open_timestamp) / 1000.0).strftime("%Y/%m/%d %H:%M:%S %Z")
                uid_timestamps.append({"uid": uid, "timestamp": open_timestamp, "date_time": date_time_readable, "timestamp_html": f'<span data-toggle="tooltip" data-placement="right" title="Timestamp: {open_timestamp}">{date_time_readable}</span>'})

    # If we found any data, write it to the report
    if user_map or uid_timestamps:
        processed_uids = []
        data_rows = []
        tsv_rows = []
        
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
        
        report = ArtifactHtmlReport(f'{category} - {artifact_name}', category)
        report.start_artifact_report(report_folder, f'{category} - {artifact_name}', description)
        report.add_script()

        report.write_minor_header("Sources")
        for file_found in files_found:
            file_path = file_found[4:] if file_found.startswith('\\\\?\\') else file_found
            report.write_raw_html(f'<li class="list-group-item bg-white"><code>{str((file_path))}</code></li>')
        report.write_raw_html('</ul><br/>')
        
        report.write_minor_header("Results")
        report.write_artifact_data_table(headers, data_rows, str(files_found[0].split(dir_sep)[0]), html_escape=False, write_location=False)
        report.end_artifact_report()
        
        # Generate a TSV file
        tsv(report_folder, headers, tsv_rows,  report_name)
        #timeline(report_folder, "Report Name", tsv_rows, headers)

    else:
        logfunc('No user history data found in Threads artifacts')
    return

def get_threads_account_details(files_found, report_folder, seeker, wrap_text, time_offset):
    pass

def get_threads_recent_searches(files_found, report_folder, seeker, wrap_text, time_offset):
    pass

def get_threads_logged_ip_addrs(files_found, report_folder, seeker, wrap_text, time_offset):
    pass