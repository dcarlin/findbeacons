#!/usr/bin/env python3
"""Search for beacon traffic in Squid access.log files"""

# Part of squidsifter by Social Exploits (https://socialexploits.com).
# Special version for SANS SEC504.

import argparse
import re
import sys

from datetime import datetime, time, timedelta, timezone

# Global object to hold application config and keep the namespace clean
config = {
    # Only process requests from a specific client
    "client": None,

    # The access.log file to read
    "log_file": "access.log",

    # Default interval (in seconds) to look for beacons
    "interval": 5,

    # Minimum number of intervals to consider a beacon
    "min_count": 10,
}

# Global object to hold field names and their descriptions
field_info = {
    "timestamp": "The time the request was made",
    "duration": "The time (in milliseconds) spent handling the request",
    "client": "The client that made the request",
    "result_code": "The Squid result code",
    "bytes": "The amount of data sent to the client",
    "method": "The request method",
    "url": "The URL the client requested",
    "user": "The identity of the requesting client (if available)",
    "hierarchy_code": "The Squid hierarchy code",
    "type": "The content type from the HTTP reply header",

}

# List of the fields in the order they appear in the access.log file
field_order = [
    "timestamp", "duration", "client", "result_code", "bytes", "method",
    "url", "user", "hierarchy_code", "type"
]

def build_regex_str(fields):
    """Builds the regular expression string for parsing each line

    Parameters:
        fields (list): A list of field names to capture

    Returns:
        str: A regular expression to capture the desired fields
    """

    # Dictionary of the regular expressions for each field
    regex_strs = {
        "timestamp": r"\d+\.\d+",
        "duration": r"\d+",
        "client": r".*?",
        "result_code": r".*?/.*?",
        "bytes": r"\d+?",
        "method": r".*?",
        "url": r".*?",
        "user": r".*?",
        "hierarchy_code": r".*?",
        "type": r".*?",
    }

    # Convert field names to lowercase
    fields = [field.lower() for field in fields]

    # Adjust the regular expression strings to capture the desired fields

    # For each field to capture
    for field in fields:

        # Make sure the field exists
        if field in regex_strs:

            # Get the regex string
            regex_str = regex_strs[field]

            # Update the regex to include parentheses for capturing
            regex_strs[field] = "({})".format(regex_str)

        # end if
    # end for

    # Handle the special case of specifying a particular client
    if config["client"]:

        # If the client should be captured, make a capture group
        if "client" in fields:
            regex_strs["client"] = "({})".format(config["client"])

        else:
            # Otherwise make it a non-capturing group
            regex_strs["client"] = "(?:{})".format(config["client"])

        # end if
    # end if

    # Build the regular expression string in field order
    regex_str = r"\s+".join([regex_strs[field] for field in field_order])

    # Return the result
    return regex_str
# end def build_regex_str

def parse_cmdline_args():
    """Parses command-line arguments and populates the global config"""

    # Create the argument parsing object
    parser = argparse.ArgumentParser()

    parser.add_argument(
        "-i",
        "--interval",
        metavar="SECS",
        default=config["interval"],
        type=int,
        help="the interval (in seconds) to consider a possible beacon"
    )


    parser.add_argument(
        "-c",
        "--min-count",
        metavar="NUM",
        default=config["min_count"],
        type=int,
        help="the minimum number of beacons to consider a URL as suspicious"
    )

    parser.add_argument(
        "client",
        metavar="CLIENT",
        help="look for beacons from CLIENT"
    )

    parser.add_argument(
        "log_file",
        metavar="FILE",
        help="the Squid access.log file to parse"
    )

    args = parser.parse_args()

    config["interval"] = args.interval
    config["min_count"] = args.min_count
    config["log_file"] = args.log_file
    config["client"] = args.client
# end def parse_cmdline_args

def open_log_file(log_file):
    """Tries to open the access.log file

    Parameters:
        log_file (str): The Squid access.log

    Returns:
        file: An open file object
    """

    try:
        file_obj = open(log_file, "r")
    except Exception as e:
        sys.stderr.write(str(e) + "\n")
        sys.stderr.write(
            "Error opening file {} (Did you make a typo?)\n".format(log_file)
        )
        sys.exit(-1)
    # end try

    return file_obj
# end def open_log_file

def find_beacons():
    """Finds beacons in a Squid access.log file"""

    regex = re.compile(build_regex_str(["timestamp", "client", "url"]))

    file_obj = open_log_file(config["log_file"])

    min_count = config["min_count"]
    interval = config["interval"]

    # Create a dictionary that will hold the urls (and ultimately) the time
    # deltas
    time_data = {}

    # First extract all of the urls for a given client, and log the timestamps
    for line in file_obj:
        current_fields = regex.findall(line)

        if not current_fields:
            continue
        # end if

        current_fields = current_fields[0]

        timestamp = float(current_fields[0])
        url = current_fields[2]

        if url in time_data:
            time_data[url].append(timestamp)
        else:
            time_data[url] = [timestamp]
        # end if
    # end for

    # Next calculate the number of requests for a given time interval
    for url in list(time_data.keys()):
        # Skip if only one timestamp (which means there isn't an interval)
        if len(time_data[url]) == 1:
            del time_data[url]
            continue
        # end if

        # Make sure they are in newest-to-oldest order
        time_data[url].sort(reverse=True)

        beacon_count = 0
        timestamps = time_data[url]
        timestamp_count = len(timestamps)
        for cur_index, timestamp in enumerate(timestamps[:-1]):
            for next_index in range(cur_index, timestamp_count - 1):
                delta = int(timestamp - timestamps[next_index])

                if delta == interval:
                    beacon_count += 1
                    break
                elif delta > interval:
                    break
                # end if
             # end for
        # end for

        if beacon_count >= min_count:
            time_data[url] = beacon_count
        else:
            del time_data[url]
        # end if
    # end for

    if time_data:
        print("Sites that had at least {} {}-second intervals".format(
            min_count, interval
        ))


        for url in time_data:
            print("{:5} - {}".format(time_data[url], url))
        # end for
    else:
        print("No sites with at least {} intervals at {} seconds".format(
            min_count, interval
        ))
    # end if

    file_obj.close()
# end def find_beacons


def main():
    """Main function if running as a standalone program"""

    parse_cmdline_args()
    find_beacons()
# end def main

if __name__ == "__main__":
    main()
# end if
