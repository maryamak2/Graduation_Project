from elasticsearch import Elasticsearch
import requests
import logging
from datetime import datetime, timedelta
import time

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

# Connect to Elasticsearch
es = Elasticsearch(["http://localhost:9200"])

# Keep track of already banned users
banned_list = set()

def check_failed_logins():
    query = {
        "size": 0,
        "query": {
            "bool": {
                "filter": [
                    {"term": {"status.keyword": "failed"}},
                    {
                        "range": {
                            "@timestamp": {
                                "gte": "now-15m/m",
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
                logging.info("No users with 3 or more failed logins in the last 3 days.")
                return

            for bucket in buckets:
                username = bucket["key"]

                # Check if the user is already banned
                if username in banned_list:
                    logging.info(f"Skipping already banned user: {username}")
                    continue

                logging.info(f"Username to be banned: {username}")

                # Send alert to backend
                backend_url = "http://127.0.0.1:8000/ban-user/"
                alert_data = {
                    "user_username": username,
                    "ban_minutes": 15
                }
                try:
                    response = requests.post(backend_url, json=alert_data)
                    if response.status_code == 200:
                        logging.info(f"Successfully sent ban alert for '{username}'!")
                        # Add the user to the banned list
                        banned_list.add(username)
                    else:
                        logging.error(f"Failed to send alert for '{username}': {response.status_code}")
                except Exception as e:
                    logging.error(f"Error sending alert for '{username}': {e}")
        else:
            logging.info("No failed login attempts matching the criteria were found.")
    except Exception as e:
        logging.error(f"Error querying Elasticsearch: {e}")

# Run the function continuously
while True:
    check_failed_logins()
    # Optionally, introduce a delay to prevent excessive querying
    time.sleep(10)