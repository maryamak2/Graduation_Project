from elasticsearch import Elasticsearch
import requests
import logging
from datetime import datetime, timedelta
import time
from apscheduler.schedulers.background import BackgroundScheduler

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

# Connect to Elasticsearch
es = Elasticsearch(["http://127.0.0.1:9200"])

# Keep track of banned users with their ban expiration time
banned_list = {}

def check_failed_logins():
    query = {
        "size": 0,
        "query": {
            "bool": {
                "filter": [
                    {"term": {"status.keyword": "FailedLogin"}},
                    {
                        "range": {
                            "@timestamp": {
                                "gte": "now-3m/m",
                                "lte": "now"
                            }
                        }
                    }
                ]
            }
        },
        "aggs": {
            "usernames": {
                "terms": {
                    "field": "username.keyword",
                    "min_doc_count": 3
                }
            }
        }
    }

    try:
        response = es.search(index="user-logins", body=query)
        if "aggregations" in response and "usernames" in response["aggregations"]:
            buckets = response["aggregations"]["usernames"]["buckets"]
            if not buckets:
                print("No users with 3 or more failed logins in the last 3 days.")
                return

            for bucket in buckets:
                Email = bucket["key"]

                # Check if the user is already banned
                if Email in banned_list:
                    print(f"Skipping already banned user: {Email}")
                    continue

                print(f"Username to be banned: {Email}")

                # Send alert to backend
                backend_url = "http://100.89.45.27:8000/ban-user/"
                alert_data = {
                    "user_username": Email,
                    "ban_minutes": 5
                }
                try:
                    response = requests.post(backend_url, json=alert_data)
                    if response.status_code == 200:
                        print(f"Successfully sent ban alert for '{Email}'!")
                        # Add the user to the banned list with expiration time
                        expiration_time = datetime.now() + timedelta(minutes=5)
                        banned_list[Email] = expiration_time
                    else:
                        print(f"Failed to send alert for '{Email}': {response.status_code}")
                except Exception as e:
                    print(f"Error sending alert for '{Email}': {e}")
        else:
            print("No failed login attempts matching the criteria were found.")
    except Exception as e:
        print(f"Error querying Elasticsearch: {e}")




def refresh_banned_list():
    current_time = datetime.now()
    expired_users = []

    for username, expiration_time in banned_list.items():
        if current_time > expiration_time:
            expired_users.append(username)

    for username in expired_users:
        print(f"Removing expired ban for user: {username}")
        del banned_list[username]

    # Print the current banned list
    if banned_list:
        print("Current banned users:")
        for username, expiration_time in banned_list.items():
            remaining_time = (expiration_time - current_time).total_seconds() / 60
            print(f"User: {username}, Ban expires in: {remaining_time:.2f} minutes")
    else:
        print("No banned users.")


# Keep track of users who have already been processed
processed_users = set()

# Function to check for suspicious edit request spikes
def check_edit_request_spike():
    query = {
        "size": 0,
        "query": {
            "bool": {
                "filter": [
                    {"term": {"Service.keyword": "PatientEdited"}},
                    {
                        "range": {
                            "@timestamp": {
                                "gte": "now-2m/m",  # Last 1 minute
                                "lte": "now"
                            }
                        }
                    }
                ]
            }
        },
        "aggs": {
            "usernames": {
                "terms": {
                    "field": "user_id",  # Aggregating by user_id
                    "min_doc_count": 2  # At least 2 requests
                }
            }
        }
    }

    try:
        response = es.search(index="user-logins", body=query)
        if "aggregations" in response and "usernames" in response["aggregations"]:
            buckets = response["aggregations"]["usernames"]["buckets"]
            for bucket in buckets:
                user_id = bucket["key"]

                if user_id not in suspicious_users:
                    logging.info(f"Flagging user as suspicious: {user_id}")
                    
                    # Send alert to Security API Endpoint
                    backend_url = "http://100.89.45.27:8000/mark-suspicious"
                    alert_data = {"doctor_id": int(user_id)}  # Ensure doctor_id is an integer

                    try:
                        api_response = requests.post(backend_url, json=alert_data)
                        if api_response.status_code == 200:
                            logging.info(f"Successfully alerted for user: {user_id}",headers={"Content-Type": "application/json"})
                            suspicious_users[user_id] = datetime.now()
                        else:
                            logging.error(f"Failed to send alert for user {user_id}: {api_response.status_code}")
                    except Exception as e:
                        logging.error(f"Error sending alert for user {user_id}: {e}")
        else:
            logging.info("No suspicious POST request activity detected.")
    except Exception as e:
        logging.error(f"Error querying Elasticsearch: {e}")
  

suspicious_users = {}

# Function to flush the list of suspicious users every 1 minute
def flush_suspicious_users():
    suspicious_users.clear()
    logging.info("Flushed suspicious user list.")

flagged_doctors = {}

def monitor_delete_spikes():
    """Detects doctors who perform 2 or more DELETE requests within 1 minute."""
    query = {
        "size": 0,
        "query": {
            "bool": {
                "filter": [
                    {"term": {"Service.keyword": "Delete a patient record"}},
                    {
                        "range": {
                            "@timestamp": {
                                "gte": "now-1m/m",
                                "lte": "now"
                            }
                        }
                    }
                ]
            }
        },
        "aggs": {
            "doctors": {
                "terms": {
                    "field": "user_id",
                    "min_doc_count": 2  # Detect at least 2 requests
                }
            }
        }
    }

    try:
        response = es.search(index="user-logins", body=query)
        if "aggregations" in response and "doctors" in response["aggregations"]:
            buckets = response["aggregations"]["doctors"]["buckets"]
            for bucket in buckets:
                doctor_id = bucket["key"]

                if doctor_id not in flagged_doctors:
                    logging.info(f"Doctor {doctor_id} flagged due to multiple DELETE requests.")
                    print(f"Doctor {doctor_id} flagged due to multiple DELETE requests.")  # Debugging
                    
                    # Send alert to Security API Endpoint
                    backend_url = "http://100.89.45.27:8000/mark-suspicious"
                    alert_data = {"doctor_id": int(doctor_id)}

                    try:
                        api_response = requests.post(backend_url, json=alert_data)
                        if api_response.status_code == 200:
                            flagged_doctors[doctor_id] = datetime.now()
                            logging.info(f"Flagged Doctor {doctor_id} successfully.")
                            print(f"Flagged Doctor {doctor_id} successfully.")  # Debugging
                        else:
                            logging.error(f"Failed to alert for Doctor {doctor_id}: {api_response.status_code}")
                            print(f"Failed to alert for Doctor {doctor_id}: {api_response.status_code}")  # Debugging
                    except Exception as e:
                        logging.error(f"Error flagging Doctor {doctor_id}: {e}")
                        print(f"Error flagging Doctor {doctor_id}: {e}")  # Debugging
        else:
            logging.info("No suspicious DELETE spike detected.")
            print("No suspicious DELETE spike detected.")  # Debugging
    except Exception as e:
        logging.error(f"Error querying Elasticsearch: {e}")
        print(f"Error querying Elasticsearch: {e}")  # Debugging


def clear_flagged_doctors():
    """Clears flagged doctors every 5 minutes."""
    flagged_doctors.clear()
    logging.info("Cleared flagged doctors.")
    print("Cleared flagged doctors.")  # Debugging



def check_OTP():
    query = {
        "size":0,
        "query": {
            "bool": {
                "filter": [
                    {"term": {"status.keyword": "ThreeFailedOTP"}},
                    {
                        "range": {
                            "@timestamp": {
                                "gte": "now-3m/m",
                                "lte": "now"
                            }
                        }
                    }
                ]
            }
        },
        "aggs": {
            "usernames": {
                "terms": {
                    "field": "username.keyword",
                    "min_doc_count": 1
                }
            }
        }
    }

    try:
        response = es.search(index="user-logins", body=query)
        if "aggregations" in response and "usernames" in response["aggregations"]:
            buckets = response["aggregations"]["usernames"]["buckets"]
            if not buckets:
                print("No users with 3 failed OTPs.")
                return

            for bucket in buckets:
                username = bucket["key"]

                # Check if the user is already banned
                if username in banned_list:
                    print(f"Skipping already banned user: {username}")
                    continue

                print(f"Username to be banned: {username}")

                # Send alert to backend
                backend_url = "http://100.89.45.27:8000/ban-user/"
                alert_data = {
                    "user_username": username,
                    "ban_minutes": 5
                }
                try:
                    response = requests.post(backend_url, json=alert_data)
                    if response.status_code == 200:
                        print(f"Successfully sent ban alert for '{username}'!")
                        # Add the user to the banned list with expiration time
                        expiration_time = datetime.now() + timedelta(minutes=5)
                        banned_list[username] = expiration_time
                    else:
                        print(f"Failed to send alert for '{username}': {response.status_code}")
                except Exception as e:
                    print(f"Error sending alert for '{username}': {e}")
        else:
            print("No failed OTP attempts matching the criteria were found.")
    except Exception as e:
        print(f"Error querying Elasticsearch: {e}")



def check_multiple_patients_added():
    query = {
        "size": 0,
        "query": {
            "bool": {
                "filter": [
                    {"term": {"status.keyword": "patient added"}},  # Looking for successful logins
                    {
                        "range": {
                            "@timestamp": {
                                "gte": "now-1m/m",  # Logins within the last 1 minute
                                "lte": "now"
                            }
                        }
                    }
                ]
            }
        },
        "aggs": {
            "emails": {
                "terms": {
                    "field": "email.keyword",  # Assuming the field is "email"
                    "min_doc_count": 2  # Look for users with 10 or more logins
                }
            }
        }
    }

    try:
        response = es.search(index="user-logins", body=query)
        if "aggregations" in response and "emails" in response["aggregations"]:
            buckets = response["aggregations"]["emails"]["buckets"]
            if not buckets:
                logging.info("No multiple POSTs in the last minute.")
                return

            for bucket in buckets:
                email = bucket["key"]

                # Check if the email is already blocked
                if email in banned_list:
                    logging.info(f"Skipping already blocked email: {email}")
                    continue

                logging.info(f"Email to be blocked: {email}")

                # Send alert to backend (FastAPI server)
                backend_url = "http://100.89.45.27:8000/ban-user/"
                alert_data = {
                    "email": email,
                    "ban_minutes": 5
                }
                try:
                    response = requests.post(backend_url, json=alert_data)
                    if response.status_code == 200:
                        logging.info(f"Successfully banned email '{email}' !")
                        # Add the email to the blocked list to prevent re-blocking in the same run
                        expiration_time = datetime.now() + timedelta(minutes=5)
                        banned_list[email] = expiration_time
                    else:
                        logging.error(f"Failed to add email '{email}' to blocked list: {response.status_code}")
                except Exception as e:
                    logging.error(f"Error sending alert for email '{email}': {e}")
        else:
            logging.info("No successful logins matching the criteria were found.")
    except Exception as e:
        logging.error(f"Error querying Elasticsearch: {e}")

def check_successful_logins():
    query = {
        "size": 0,
        "query": {
            "bool": {
                "filter": [
                    {"term": {"status.keyword": "SUCCESSFUL"}},  # Looking for successful logins
                    {
                        "range": {
                            "@timestamp": {
                                "gte": "now-1m/m",  # Logins within the last 1 minute
                                "lte": "now"
                            }
                        }
                    }
                ]
            }
        },
        "aggs": {
            "emails": {
                "terms": {
                    "field": "email.keyword",  # Assuming the field is "email"
                    "min_doc_count": 5  # Look for users with 10 or more logins
                }
            }
        }
    }

    try:
        response = es.search(index="user-logins", body=query)
        if "aggregations" in response and "emails" in response["aggregations"]:
            buckets = response["aggregations"]["emails"]["buckets"]
            if not buckets:
                logging.info("No users with 5 or more successful logins in the last minute.")
                return

            for bucket in buckets:
                email = bucket["key"]

                # Check if the email is already blocked
                if email in banned_list:
                    logging.info(f"Skipping already blocked email: {email}")
                    continue

                logging.info(f"Email to be blocked: {email}")

                # Send alert to backend (FastAPI server)
                # Send alert to backend (FastAPI server)
                backend_url = "http://100.89.45.27:8000//ban-user/"
                alert_data = {
                    "user_username": email,
                    "ban_minutes": 5
                }
                try:
                    response = requests.post(backend_url, json=alert_data)
                    if response.status_code == 200:
                        logging.info(f"Successfully added email '{email}' to blocked list!")
                        # Add the email to the blocked list to prevent re-blocking in the same run
                        banned_list.add(email)
                    else:
                        logging.error(f"Failed to add email '{email}' to blocked list: {response.status_code}")
                except Exception as e:
                    logging.error(f"Error sending alert for email '{email}': {e}")
        else:
            logging.info("No successful logins matching the criteria were found.")
    except Exception as e:
        logging.error(f"Error querying Elasticsearch: {e}")


# Flush doctors that were flagged more than 5 minutes ago
def flush_flagged_doctors():
    expiration_time = timedelta(minutes=5)
    now = datetime.now()
    to_keep = {}
    for doc, ts in flagged_doctors.items():
        if now - ts <= expiration_time:
            to_keep[doc] = ts
    flagged_doctors.clear()
    flagged_doctors.update(to_keep)
    logging.info("Flagged doctors flushed")
    
    
# Scheduler to run periodic tasks
scheduler = BackgroundScheduler()
scheduler.add_job(clear_flagged_doctors, 'interval', minutes=5)  # Clear flagged doctors
# scheduler.add_job(monitor_delete_spikes, 'interval', minutes=1)  # Monitor delete spikes
scheduler.start()

# Run the function continuously
while True:
    check_successful_logins()
    check_OTP()
    check_failed_logins()
    refresh_banned_list()
    check_edit_request_spike()
    check_successful_logins()
    check_multiple_patients_added()
    monitor_delete_spikes()
    flush_flagged_doctors()
    flush_suspicious_users()
    # Optionally, introduce a delay to prevent excessive querying
    time.sleep(20)
    

 