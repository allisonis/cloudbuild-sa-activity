import base64
import json 
import requests

# slack webhook URL
SLACK_WEBHOOK_URL = ""
HEADERS = {'Content-type': 'application/json'}

#Process incoming pubsub filtered logs and post an alert to slack.
def cloudbuild_service_account_alerts(event, context):
    # Base64 decode incoming pubsub event messages.
    pubsub_message = base64.b64decode(event['data']).decode('utf-8')
    pubsub_message = json.loads(pubsub_message)

    alert_dict = {
        'log_name': pubsub_message['logName'],
        'resource_type': pubsub_message['resource'],
        'caller_ip': pubsub_message['requestMetadata']['callerIp']
    }
    
    slack_alert_formatted = "Potentially malicious CloudBuild request sent from IP: {}, Log Name {}".format(alert_dict['caller_ip'], alert_dict['log_name'])
    slack_alert = json.dumps({"text": pubsub_message})

    # Send alert to Slack 
    response = requests.post(url=SLACK_WEBHOOK_URL, data=slack_alert, headers=HEADERS)
    if response.status_code!=200:
        raise ValueError ('Request failed to send with error:{} {}'.format(response.status_code, response.text))
    print(response)

cloudbuild_service_account_alerts_test()