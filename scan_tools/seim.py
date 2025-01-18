import win32evtlog  # Requires pywin32
from datetime import datetime
import ctypes  # For displaying alert messages

# Function to show an alert message box
def show_alert(message):
    ctypes.windll.user32.MessageBoxW(0, message, "Security Alert", 0x40 | 0x1)

# Function to read and monitor event logs in real-time
def read_event_logs(log_types=["Application", "System", "Security", "Setup", "Microsoft-Windows-PowerShell/Operational"]):
    # Open the event logs specified in the log_types list
    log_handles = {log_type: win32evtlog.OpenEventLog(None, log_type) for log_type in log_types}
    flags = win32evtlog.EVENTLOG_FORWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
    start_time = datetime.now()
    displayed_events = set()  # Track displayed events to avoid duplicates

    print(f"Monitoring logs ({', '.join(log_types)}) in real-time. Press Ctrl+C to stop.\n{'-'*50}")

    try:
        while True:
            for log_type, log_handle in log_handles.items():
                events = win32evtlog.ReadEventLog(log_handle, flags, 0)
                for event in events:
                    event_id = event.EventID
                    event_time = event.TimeGenerated.Format()
                    event_source = event.SourceName
                    event_category = event.EventCategory
                    event_description = "\n".join(event.StringInserts) if event.StringInserts else "No description available."

                    # Convert event time to datetime and filter older events
                    event_datetime = datetime.strptime(event_time, '%a %b %d %H:%M:%S %Y')
                    if event_datetime < start_time:
                        continue  # Skip events that occurred before the script started

                    # Use event ID and time as a unique identifier to avoid duplicates
                    event_key = (event_id, event_time)
                    if event_key in displayed_events:
                        continue
                    displayed_events.add(event_key)

                    # Check for specific event IDs and trigger alerts

                    # Detect failed login attempt (Event ID 4625)
                    if log_type == "Security" and event_id == 4625:
                        alert_message = (f"Failed Login Attempt Detected!\n\n"
                                         f"Timestamp: {event_time}\n"
                                         f"Event ID: {event_id}\n"
                                         f"Source: {event_source}\n"
                                         f"Category: {event_category}\n\n"
                                         f"Description:\n{event_description}")
                        show_alert(alert_message)

                    # Detect application installation (Event ID 11707)
                    if log_type == "Setup" and event_source in ["MsiInstaller", "Windows Installer"] and event_id == 11707:
                        alert_message = (f"Successful Installation Detected!\n\n"
                                         f"Timestamp: {event_time}\n"
                                         f"Event ID: {event_id}\n"
                                         f"Source: {event_source}\n"
                                         f"Category: {event_category}\n\n"
                                         f"Description:\n{event_description}")
                        show_alert(alert_message)

                    # Detect application installation failure (Event ID 11708)
                    if log_type == "Setup" and event_source in ["MsiInstaller", "Windows Installer"] and event_id == 11708:
                        alert_message = (f"Application Installation Failure Detected!\n\n"
                                         f"Timestamp: {event_time}\n"
                                         f"Event ID: {event_id}\n"
                                         f"Source: {event_source}\n"
                                         f"Category: {event_category}\n\n"
                                         f"Description:\n{event_description}")
                        show_alert(alert_message)

                    # Detect antivirus scan completion (Event ID 1116)
                    if log_type == "Security" and event_id == 1116:
                        alert_message = (f"Antivirus Scan Completed!\n\n"
                                         f"Timestamp: {event_time}\n"
                                         f"Event ID: {event_id}\n"
                                         f"Source: {event_source}\n"
                                         f"Category: {event_category}\n\n"
                                         f"Description:\n{event_description}")
                        show_alert(alert_message)

                    # Detect object deletion (Event ID 4660)
                    if log_type == "Security" and event_id == 4660:
                        alert_message = (f"Object Deletion Detected!\n\n"
                                         f"Timestamp: {event_time}\n"
                                         f"Event ID: {event_id}\n"
                                         f"Source: {event_source}\n"
                                         f"Category: {event_category}\n\n"
                                         f"Description:\n{event_description}")
                        show_alert(alert_message)

                    # Detect attempted password change (Event ID 4723)
                    if log_type == "Security" and event_id == 4723:
                        alert_message = (f"Attempted Password Change Detected!\n\n"
                                         f"Timestamp: {event_time}\n"
                                         f"Event ID: {event_id}\n"
                                         f"Source: {event_source}\n"
                                         f"Category: {event_category}\n\n"
                                         f"Description:\n{event_description}")
                        show_alert(alert_message)

                    # Detect user account creation (Event ID 4720)
                    if log_type == "Security" and event_id == 4720:
                        alert_message = (f"New User Account Created!\n\n"
                                         f"Timestamp: {event_time}\n"
                                         f"Event ID: {event_id}\n"
                                         f"Source: {event_source}\n"
                                         f"Category: {event_category}\n\n"
                                         f"Description:\n{event_description}")
                        show_alert(alert_message)

                    # Detect PowerShell Startup (Event ID 400)
                    if log_type == "Microsoft-Windows-PowerShell/Operational" and event_id == 400:
                        alert_message = (f"PowerShell Opened!\n\n"
                                         f"Timestamp: {event_time}\n"
                                         f"Event ID: {event_id}\n"
                                         f"Source: {event_source}\n"
                                         f"Category: {event_category}\n\n"
                                         f"Description:\n{event_description}")
                        show_alert(alert_message)

                    # Detect PowerShell Module Logging (Event ID 4103)
                    if log_type == "Microsoft-Windows-PowerShell/Operational" and event_id == 4103:
                        alert_message = (f"PowerShell Module Logged!\n\n"
                                         f"Timestamp: {event_time}\n"
                                         f"Event ID: {event_id}\n"
                                         f"Source: {event_source}\n"
                                         f"Category: {event_category}\n\n"
                                         f"Description:\n{event_description}")
                        show_alert(alert_message)

                    # Detect Service Start or Stop (Event ID 7036)
                    if log_type == "System" and event_id == 7036:
                        alert_message = (f"Service Start or Stop Detected!\n\n"
                                         f"Timestamp: {event_time}\n"
                                         f"Event ID: {event_id}\n"
                                         f"Source: {event_source}\n"
                                         f"Category: {event_category}\n\n"
                                         f"Description:\n{event_description}")
                        show_alert(alert_message)

                    # Formatted console output for all events
                    print(f"Timestamp : {event_time}")
                    print(f"Log Type  : {log_type}")
                    print(f"Event ID  : {event_id}")
                    print(f"Source    : {event_source}")
                    print(f"Category  : {event_category}")
                    print(f"Details   : {event_description}")
                    print(f"{'-'*50}\n")
                    
    except KeyboardInterrupt:
        print("Real-time monitoring stopped.")
    finally:
        # Close all log handles after the script ends
        for handle in log_handles.values():
            win32evtlog.CloseEventLog(handle)

# Run the function with specified log types
read_event_logs(["Application", "System", "Security", "Setup", "Microsoft-Windows-PowerShell/Operational"])
