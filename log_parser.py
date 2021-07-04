import pandas as pd
import numpy as np
import os
import glob
import magic  # pip install python-magic, pip install libmagic, pip install python-magic-bin (windows)
import re
from dns import resolver, reversename  # pip install dnspython
import searchconsole  # pip install git, pip install git+https://github.com/joshcarty/google-searchconsole
import time, datetime

# test setting, false unless testing
test = False

# Get type of log file from user input
def selectFormat():

    log_formats = ["amazon_elb", "apache_combined", "iis_w3c_mandatory"]

    def selectFromDict():
        index = 0

        print(
            "Please select log format by inputting the corresponding number, e.g. 1: "
        )
        for log_format in log_formats:
            index += 1
            print(str(index) + ") " + log_format)

        try:
            inputNo = int(input("Log format: ")) - 1
            if inputNo < len(log_formats) and inputNo >= 0:
                selected = log_formats[abs(inputNo)]
                print("Selected log format: " + selected)
                return selected
            else:
                print("Not valid format number")
                return selectFromDict()

        except:
            print("That's not an number!")
            return selectFromDict()

    return "apache_combined" if test else selectFromDict()


# GSC authentication
def webproperty():
    # GSC auth location
    credentials = "./credentials.json"
    params = {"serialize": credentials}
    if os.path.exists(credentials):
        params["credentials"] = params.pop("serialize")
    return searchconsole.authenticate(client_config="./client_secrets.json", **params)


# Import to pandas and basic parsing depending on log file format
def parseLog():
    # get domain from user input
    whole_url = (
        "https://builtvisible.com"
        if test
        else input(
            "Please enter full domain with protocol and no trailing slash e.g. https://builtvisible.com: "
        )
    )

    # domain variants
    subdomain = re.sub(r"^(http|https)://", "", whole_url)
    domain = whole_url + "/"
    log_format = selectFormat()

    print("Parsing Googlebot data...")

    # start counting script execution time
    global startTime
    startTime = time.time()

    if log_format == "apache_combined":
        df = pd.read_csv(
            "./logs_export/googlebot.txt",
            sep="\s+",
            error_bad_lines=False,
            header=None,
            low_memory=False,
        )
        df.drop([1, 2, 4], axis=1, inplace=True)
        df[3] = df[3].str.replace("[", "", regex=False)
        df[["Date", "Time"]] = df[3].str.split(
            ":", 1, expand=True
        )  # split time stamp into two
        df[["Request Type", "URI", "Protocol"]] = df[5].str.split(
            " ", 2, expand=True
        )  # split uri request into columns
        df.drop([3, 5], axis=1, inplace=True)
        df.rename(
            columns={
                0: "IP",
                6: "Status Code",
                7: "Bytes",
                8: "Referrer URL",
                9: "User Agent",
            },
            inplace=True,
        )
        df["Full URL"] = whole_url + df["URI"]
        df["Date"] = pd.to_datetime(df["Date"])
        df[["Status Code", "Bytes"]] = df[["Status Code", "Bytes"]].apply(
            pd.to_numeric, errors="coerce"
        )
        df = df[
            [
                "Date",
                "Time",
                "Request Type",
                "Full URL",
                "URI",
                "Status Code",
                "Protocol",
                "Referrer URL",
                "Bytes",
                "User Agent",
                "IP",
            ]
        ]

    elif log_format == "iis_w3c_mandatory":
        df = pd.read_csv(
            "./logs_export/googlebot.txt",
            sep="\s+",
            error_bad_lines=False,
            header=None,
            low_memory=False,
        )
        df.rename(
            columns={0: "Date", 1: "Time", 2: "URI", 3: "User Agent", 4: "Status Code"},
            inplace=True,
        )
        df["Full URL"] = whole_url + df["URI"]
        df["Date"] = pd.to_datetime(df["Date"])
        df["Status Code"] = df["Status Code"].apply(pd.to_numeric, errors="coerce")
        df = df[["Date", "Time", "Full URL", "URI", "Status Code", "User Agent"]]

    elif log_format == "amazon_elb":
        df = pd.read_csv(
            "./logs_export/googlebot.txt",
            sep="\s+",
            error_bad_lines=False,
            header=None,
            low_memory=False,
        )
        df.drop([1, 3, 4, 5, 7, 9, 13, 14], axis=1, inplace=True)
        df[["Date", "Time"]] = df[0].str.split(
            "T", 1, expand=True
        )  # split time stamp into two
        df[["Request Type", "Full URL", "Protocol"]] = df[11].str.split(
            " ", 2, expand=True
        )  # split uri request into columns
        df.drop([0, 11], axis=1, inplace=True)
        df.rename(
            columns={
                2: "IP",
                6: "Time Taken",
                8: "Status Code",
                10: "Bytes",
                12: "User Agent",
            },
            inplace=True,
        )
        df["URI"] = df["Full URL"].str.replace(
            whole_url, "", regex=False
        )  # strip off domain to give URI
        df["Date"] = pd.to_datetime(df["Date"])
        df["Time"] = df["Time"].str.split(".").str[0]
        df["IP"] = df["IP"].str.split(":").str[0]
        df[["Status Code", "Time Taken", "Bytes"]] = df[
            ["Status Code", "Time Taken", "Bytes"]
        ].apply(pd.to_numeric, errors="coerce")
        df = df[
            [
                "Date",
                "Time",
                "Request Type",
                "Full URL",
                "URI",
                "Status Code",
                "Protocol",
                "Time Taken",
                "Bytes",
                "User Agent",
                "IP",
            ]
        ]

    filteredData(df, log_format, domain)


# Validating Googlebot and merging in GSC
def filteredData(master, log_format, domain):
    print("Validating Googlebot...")

    # evaluate DNS from filtered ips
    # if 3.9 update to: str(resolver.resolve(reversename.from_address(ip), "PTR")[0])
    def reverseDns(ip):
        try:
            return str(resolver.query(reversename.from_address(ip), "PTR")[0])
        except:
            return "N/A"

    # only validate if the log format has ip included
    if log_format != "iis_w3c_mandatory":

        logs_filtered = master.drop_duplicates(
            ["IP"]
        ).copy()  # create DF with dupliate ips filtered for check

        logs_filtered["DNS"] = logs_filtered["IP"].apply(
            reverseDns
        )  # create DNS column with the reverse IP DNS result

        logs_filtered = master.merge(
            logs_filtered[["IP", "DNS"]], how="left", on=["IP"]
        )  # merge DNS column to full logs matching IP

        if any(
            logs_filtered["DNS"].str.contains("googlebot.com")
        ):  # conditional in case there are no Googlebot requests

            logs_filtered = logs_filtered[
                logs_filtered["DNS"].str.contains("googlebot.com")
            ]  # filter to verified Googlebot

        else:
            print("Sorry, no valid Googlebot requests were detected!")
            exit()

        logs_filtered.drop(["IP", "DNS"], axis=1, inplace=True)  # drop dns/ip columns

    else:
        logs_filtered = master

    # extract subfolder from the URI
    logs_filtered["Subfolder"] = (
        logs_filtered["URI"].str.extract(r"/(.*?)/", expand=False).fillna("Root URL")
    )

    # parameter boolean column
    logs_filtered["Parameter Status"] = logs_filtered.apply(
        lambda x: "?" in x.URI, axis=1
    )

    try:
        if os.path.exists("./client_secrets.json"):
            gsc_df = pd.DataFrame(
                data=webproperty()[domain]
                .query.range(start="today", days=-31)
                .dimension("page")
                .get()
            )  # get df of GSC data

            # merge GSC data to main df
            logs_filtered = logs_filtered.merge(
                gsc_df, how="left", left_on="Full URL", right_on="page"
            )
            logs_filtered.drop("page", axis=1, inplace=True)

    except AttributeError:
        print(
            "WARNING: GSC data pull failed! Do you have access to the domain in your account?"
        )

    # unique URLs for list crawl
    unique_urls = logs_filtered["Full URL"].drop_duplicates()
    unique_urls.to_csv("./logs_export/urls_for_crawl.csv", index=False, header=False)

    dataPivots(logs_filtered)


# Extract Googlebot requests from text files
def extractGooglebot():
    print("Extracting Googlebot requests...")

    # function to detect mime type of files
    def file_type(file_path):
        mime = magic.from_file(file_path, mime=True)
        return mime

    # generate list of files including recursive search to child subfolders in case logs are in multiple folders
    files = glob.glob("**/*.*", recursive=True)

    # ignore the export folder if script has already been run
    files = [file for file in files if not "logs_export" in file]

    # detect mime type
    file_types = [file_type(file) for file in files]

    # create dictionary of file name and type
    file_dict = dict(zip(files, file_types))

    # create list of txt and csv files for processing
    uncompressed = []

    def file_identifier(file):
        for key, value in file_dict.items():
            if file in value:
                uncompressed.append(key)

    while file_identifier("text/plain"):
        file_identifier("text/plain") in file_dict

    # create export folder
    if not os.path.exists("./logs_export"):
        os.makedirs("./logs_export")

    # search files for googlebot and write to combined file
    pattern = "Googlebot"
    new_file = open("./logs_export/googlebot.txt", "w", encoding="utf8")

    for txt_files in uncompressed:
        with open(txt_files, "r", encoding="utf8") as text_file:
            for line in text_file:
                if re.search(pattern, line):
                    new_file.write(line)

    parseLog()


# Create status, user agent, url, request, bytes and avg pivots
def dataPivots(master):
    print("Generating pivots...")

    # status code pivots
    status_code = (
        master.groupby("Status Code")
        .agg("size")
        .sort_values(ascending=False)
        .reset_index()
    )
    status_code.rename(columns={0: "# Requests"}, inplace=True)

    status_code_date = pd.pivot_table(
        master, index=["Status Code"], columns=["Date"], aggfunc="size", fill_value=0
    )

    status_code_url = pd.pivot_table(
        master,
        index=["Full URL"],
        columns=["Status Code"],
        aggfunc="size",
        fill_value=0,
    )

    # user agent pivots
    user_agent = (
        master.groupby("User Agent")
        .agg("size")
        .sort_values(ascending=False)
        .reset_index()
    )
    user_agent.rename(columns={0: "# Requests"}, inplace=True)

    user_agent_date = pd.pivot_table(
        master, index=["User Agent"], columns=["Date"], aggfunc="size", fill_value=0
    )

    user_agent_url = pd.pivot_table(
        master,
        index=["User Agent"],
        values=["Full URL"],
        columns=["Date"],
        aggfunc=pd.Series.nunique,
        fill_value=0,
    )

    user_agent_status = pd.pivot_table(
        master,
        index=["User Agent"],
        columns=["Status Code"],
        aggfunc="size",
        fill_value=0,
    )

    # url pivots
    url_count = (
        master.groupby("Full URL")
        .agg("size")
        .sort_values(ascending=False)
        .reset_index()
    )
    url_count.rename(columns={0: "# Requests"}, inplace=True)

    url_count_date = (
        master.groupby("Date").agg("size").sort_values(ascending=False).reset_index()
    )
    url_count_date.rename(columns={0: "# Requests"}, inplace=True)

    url_range = [0, 1, 10, 100, 500, 1000, np.inf]
    url_grouped_ranges = (
        url_count.groupby(pd.cut(url_count["# Requests"], bins=url_range, precision=0))
        .agg("size")
        .reset_index()
    )
    url_grouped_ranges.rename(columns={0: "# URLs"}, inplace=True)

    # subfolder pivots
    subfolder_count = (
        master.groupby("Subfolder")
        .agg("size")
        .sort_values(ascending=False)
        .reset_index()
    )
    subfolder_count.rename(columns={0: "# Requests"}, inplace=True)

    subfolder_count_date = pd.pivot_table(
        master, index=["Subfolder"], columns=["Date"], aggfunc="size", fill_value=0
    )

    # dataframes in a dict with key as name. Two dicts depending on whether index is required
    sheet_names_no_index = {
        "Requests Per Day": url_count_date,
        "Requests Per URL": url_count,
        "Aggregated Requests Per URL": url_grouped_ranges,
        "Requests Per Subfolder": subfolder_count,
        "Request Status Codes": status_code,
        "Request User Agents": user_agent,
    }

    sheet_names = {
        "Subfolder Requests Per Day": subfolder_count_date,
        "Request Status Codes Per Day": status_code_date,
        "URL Status Codes": status_code_url,
        "User Agent Requests Per Day": user_agent_date,
        "User Agent Requests Unique URLs": user_agent_url,
        "User Agent Status Codes": user_agent_status,
    }

    writeToExcel(
        master, sheet_names_no_index, sheet_names,
    )


# Create a Pandas Excel writer using XlsxWriter as the engine
def writeToExcel(
    master, sheet_names_no_index, sheet_names,
):

    print("Writing to file...")

    writer = pd.ExcelWriter(
        "./logs_export/logs_export.xlsx",
        engine="xlsxwriter",
        datetime_format="dd/mm/yyyy",
        options={"strings_to_urls": False},
    )

    # write master sheet to Excel if under Excel row limit or CSV if over limit
    if len(master) <= 1048576:
        master.to_excel(writer, sheet_name="Master", index=False)
    else:
        master.to_csv("./logs_export/logs_export.csv", index=False)

    # loop through and put each on a specific sheet
    for sheet, name in sheet_names_no_index.items():
        name.head(1048576).to_excel(writer, sheet_name=sheet, index=False)

    for sheet, name in sheet_names.items():
        name.head(1048576).to_excel(writer, sheet_name=sheet)

    # conditional exports

    # request type pivots
    if "Request Type" in master.columns:
        request_type = (
            master.groupby("Request Type")
            .agg("size")
            .sort_values(ascending=False)
            .reset_index()
        )
        request_type.rename(columns={0: "# Requests"}, inplace=True)

    if "Request Type" in master.columns:
        request_type.to_excel(writer, sheet_name="Request Types", index=False)

    # bytes pivots
    if "Bytes" in master.columns:
        bytes_subfolder = pd.pivot_table(
            master, index=["Subfolder"], values=["Bytes"], aggfunc=np.mean, fill_value=0
        ).astype(int)
        byte_range = [
            0,
            50000,
            100000,
            200000,
            500000,
            1000000,
            np.inf,
        ]  # ranges/bins for bytes
        bytes_grouped_ranges = (
            master.groupby(pd.cut(master["Bytes"], bins=byte_range, precision=0))
            .agg("size")
            .reset_index()
        )
        bytes_grouped_ranges.rename(columns={0: "# Requests"}, inplace=True)

    if "Bytes" in master.columns:
        bytes_subfolder.to_excel(writer, sheet_name="Avg Bytes Per Subfolder")
        bytes_grouped_ranges.to_excel(
            writer, sheet_name="Bytes Per Request", index=False
        )

    # avg time taken pivots
    if "Time Taken" in master.columns:
        time_taken_subfolder = pd.pivot_table(
            master,
            index=["Subfolder"],
            values=["Time Taken"],
            aggfunc=np.mean,
            fill_value=0,
        ).astype(int)
        time_taken_date = pd.pivot_table(
            master,
            index=["Subfolder"],
            values=["Time Taken"],
            columns=["Date"],
            aggfunc=np.mean,
            fill_value=0,
        ).astype(int)
        time_taken_range = [
            0,
            100,
            250,
            500,
            1000,
            2000,
            np.inf,
        ]  # ranges/bins for time taken
        time_taken_grouped_ranges = (
            master.groupby(
                pd.cut(master["Time Taken"], bins=time_taken_range, precision=0)
            )
            .agg("size")
            .reset_index()
        )
        time_taken_grouped_ranges.rename(columns={0: "# Requests"}, inplace=True)

    if "Time Taken" in master.columns:
        time_taken_subfolder.to_excel(
            writer, sheet_name="Avg Request Time Per Subfolder"
        )
        time_taken_date.to_excel(writer, sheet_name="Request Time Per Day")
        time_taken_grouped_ranges.to_excel(
            writer, sheet_name="Time Taken Per Request", index=False
        )

    # close the Pandas Excel writer and output the Excel file
    writer.save()

    # script execution time
    timer = str(datetime.timedelta(seconds=round(time.time() - startTime)))
    print("The script took " + timer + " seconds!")


if __name__ == "__main__":
    extractGooglebot()
