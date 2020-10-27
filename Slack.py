import requests
import iso8601
import os
from typing import List

slack_webhook_url = os.getenv('SLACK_WEBHOOK')
ROV = "Drop Announcement\nhttps:///drop_announcement?prefix="
ROVPP = "Create Blackhole\nhttps:///create_blackhole?prefix="

'''
    This will post a messege to slack about a hijack.
    
    It is expected that recieved_from_asn is a integer, recomended policies and actions are lists of strings, and all others are strings
    Times are expected to be strings in iso8601 format
    
    Dependencies: requests and iso8601

    Example call: hijackNotification("subprefix_hijack", "1.2.3.0/24", "2341, 1010, 1011, 286, 4040", "2341", "https://bgpstream.com/event/228898", "2020-03-16T17:38:48+00:00", "", ["ROV"], ["Drop Announcement"])
'''

def gen_action_url(ROVorPP, prefix, domain):
    if ROVorPP == ROV:
        return ROVorPP[:26] + domain + ROVorPP[26:] + prefix
    elif ROVorPP == ROVPP:
        return ROVorPP[:25] + domain + ROVorPP[25:] + prefix

def slackHijackNotification(hijack_type: str, prefix: str, as_path: str, recieved_from_asn: int, hijack_url: str, start_time: str, end_time: str, recommended_policies: List[str], recommended_actions: List[str], victim_origin_name: str, attacker_origin_name: str, pass_rov: bool, on_blacklist: bool, on_whitelist: bool, chance_of_hijack: float):
    policies = ""
    actions = ""

    #Format the string to an unordered dashed list
    for s in recommended_policies:
        policies += s + "\n"

    for s in recommended_actions:
        actions += s + "\n"

    #subprefix_hijack -> Subprefix Hijack
    hijack_type = hijack_type.replace("_", " ").title()

    payload = {
        "blocks": [
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": "*A new " + hijack_type + " has been detected on prefix " + prefix + "*"
                }
            },
            {
                "type": "divider"
            },
            {
                "type": "section",
                "fields": [
                    {
                        "type": "mrkdwn",
                        "text": "*Prefix*\n" + prefix
                    },

                    {
                        "type": "mrkdwn",
                        "text": "*Hijack Type*\n" + hijack_type
                    },

                    {
                        "type": "mrkdwn",
                        "text": "*Path*\n" + as_path
                    },

                    {
                        "type": "mrkdwn",
                        "text": "*Received From ASN*\n" + str(recieved_from_asn)
                    },

                    {
                        "type": "mrkdwn",
                        "text": "*Hijack url*\n" + hijack_url
                    },
                    
                    {
                        "type": "mrkdwn",
                        "text": "*Victim Origin Name*\n" + victim_origin_name
                    },

                    {
                        "type": "mrkdwn",
                        "text": "*Attacker Origin Name*\n" + attacker_origin_name
                    }
                ]
            },
            {
                "type": "divider"
            },
            {
                "type": "section",
                "fields": [                    
                    {
                        "type": "mrkdwn",
                        "text": "*Pass ROV*\n" + str(pass_rov)
                    },

                    {
                        "type": "mrkdwn",
                        "text": "*On Blacklist*\n" + str(on_blacklist)
                    },
                    
                    {
                        "type": "mrkdwn",
                        "text": "*On Whitelist*\n" + str(on_whitelist)
                    },

                    {
                        "type": "mrkdwn",
                        "text": "*Chance of being hijacked*\n" + str(int(chance_of_hijack * 100)) + "%"
                    }
                ]
            },
            
            {
                "type": "divider"
            },

            {
                "type": "section",
                "fields": [
                    {
                        "type": "mrkdwn",
                        "text": "*Start*\n" + iso8601.parse_date(start_time).strftime("%m/%d/%Y, %H:%M:%S")
                    },
                    {
                        "type": "mrkdwn",
                        "text": "*End*\n" + ("null" if end_time == "" else iso8601.parse_date(end_time).strftime("%m/%d/%Y, %H:%M:%S"))
                    }
                ]
            },

            {
                "type": "divider"
            },
            {
                "type": "section",
                "fields": [
                    {
                        "type": "mrkdwn",
                        "text": "*Recommended Policies*\n" + policies
                    },
                    {
                        "type": "mrkdwn",
                        "text": "*Recommended Actions*\n" + actions
                    }
                ]
            }
        ]
    }

    requests.post(slack_webhook_url, json=payload)
    
action = [gen_action_url(ROV, "1.2.3.0/23", "12kds.rovppdashboard.com")]
slackHijackNotification("subprefix_hijack", "79.98.188.0/23", "49605, 9002, 31323", "31323", "https://bgpstream.com/event/238036", "2020-05-28T12:10:40+00:00", "", ["ROV++"], action, "INNFLOW-CH-001, CH", "UNNET-AS, RU", False, True, False, .9)
