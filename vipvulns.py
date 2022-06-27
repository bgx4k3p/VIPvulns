import time
import pandas as pd
import re
import requests
from urllib3.exceptions import InsecureRequestWarning

# Supress warnings from web requests
requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)


def scrape_cisa_alerts(y):
    """
    Function to retrieve all alerts from US-CERT for a given year and identify referenced CVEs. With this approach the
    entire list of publications is retrieved, unlike using RSS only returns the 10 most recent entries.
    :param y: String parameter for specifying year to query
    :return:
    """
    cisa_url = f'https://www.cisa.gov/uscert/ncas/alerts/{y}'
    alerts_list = []

    # Retrieve data
    r = requests.get(cisa_url, verify=False)

    # Find the full list of published alerts within the specified year using Regex
    alert_matches = re.findall(r'href.*(/ncas/alerts/.*hreflang.*)</a>', r.text)

    # Exit if no results
    if len(alert_matches) == 0:
        print(f'There are no alerts currently available for {y}.')
        exit()

    # Analyze the list of alerts
    for i in alert_matches:

        alert = dict()
        alert['intel_source'] = 'US-CERT'
        alert['alert_id'] = i.split('"')[0].split('/')[3]
        alert['alert_title'] = i.split('>')[1].strip()
        alert['alert_url'] = f'https://www.cisa.gov/uscert/ncas/alerts/{alert["alert_id"]}'

        # Retrieve additional details for each alert
        r = requests.get(alert['alert_url'], verify=False)

        # Find Published and Revised dates with Regex
        dates = re.findall(r'release date.*', r.text)[0]
        alert['alert_published'] = dates.split('|')[0].split(':')[1].strip()

        try:
            alert['alert_revised'] = dates.split('|')[1].split(':')[1].strip()
        except:
            alert['alert_revised'] = ''

        # Search for CVEs with Regex
        cve_matches = re.findall(r'[Cc][Vv][Ee]-\d{4}-\d{4,7}', r.text)
        alert['cve'] = []

        # Filter unique CVEs
        for cve in cve_matches:
            if cve not in alert['cve']:
                alert['cve'].append(cve.upper())

        # Add info to master list
        alerts_list.append(alert)
    return alerts_list


def get_cve_details(cveId, apiKey):
    """
    Function to retrieve CVE details from NVD database. Optional API key can be used to speed up throttling.
    Get free API key here https://nvd.nist.gov/general/news/API-Key-Announcement
    :param cveId:
    :param apiKey:
    :return:
    """
    if apiKey == '':
        parameters = {'addOnes': None}
        throttle = 8  # seconds between API calls
    else:
        parameters = {'addOnes': None, 'key': apiKey}
        throttle = 0.6  # seconds between API calls

    # Throttle API requests
    time.sleep(throttle)

    # Retrieve data
    r = requests.get(f'https://services.nvd.nist.gov/rest/json/cve/1.0/{cveId}', verify=False, params=parameters)

    # Retry 1 more time if any connection issues due to API rate limiting or exit
    if r.status_code != 200:
        # Sleep 10 seconds and try again
        print(f'\t\tRetrying {cveId}')
        time.sleep(10)
        r = requests.get(f'https://services.nvd.nist.gov/rest/json/cve/1.0/{cveId}', verify=False, params=parameters)

        if r.status_code != 200:
            print(f'\tError {r.status_code}! Try again later.')
            exit()

    data = r.json()['result']['CVE_Items'][0]

    # Parse the info
    info = dict()
    info['cve'] = cveId.upper()
    info['description'] = data['cve']['description']['description_data'][0]['value']
    info['publishedDate'] = data['publishedDate']
    info['severity'] = data['impact']['baseMetricV3']['cvssV3']['baseSeverity']
    info['cvss'] = data['impact']['baseMetricV3']['cvssV3']['baseScore']
    info['attackVector'] = data['impact']['baseMetricV3']['cvssV3']['attackVector']
    info['attackComplexity'] = data['impact']['baseMetricV3']['cvssV3']['attackComplexity']
    info['privilegesRequired'] = data['impact']['baseMetricV3']['cvssV3']['privilegesRequired']
    info['userInteraction'] = data['impact']['baseMetricV3']['cvssV3']['userInteraction']
    info['scope'] = data['impact']['baseMetricV3']['cvssV3']['scope']
    info['confidentialityImpact'] = data['impact']['baseMetricV3']['cvssV3']['confidentialityImpact']
    info['integrityImpact'] = data['impact']['baseMetricV3']['cvssV3']['integrityImpact']
    info['availabilityImpact'] = data['impact']['baseMetricV3']['cvssV3']['availabilityImpact']
    info['exploitabilityScore'] = data['impact']['baseMetricV3']['exploitabilityScore']
    info['impactScore'] = data['impact']['baseMetricV3']['impactScore']

    # Add fields for affected product CPEs/Vendors and Product names
    cpe_list = []
    vendor_list = []
    product_list = []

    # Search for CPE patterns with Regex
    cpe_matches = re.findall(r'cpe23Uri":"(.*?)"', r.text)
    for cpe in cpe_matches:
        vendor = cpe.split(':')[3]
        product = cpe.split(':')[4].replace('\\', '').replace('!', '')

        # Filter unique CPE/Vendor/Product
        if cpe not in cpe_list:
            cpe_list.append(cpe)
        if vendor not in vendor_list:
            vendor_list.append(vendor)
        if product not in product_list:
            product_list.append(product)

    info['affectedVendors'] = '\n'.join(vendor_list)
    info['affectedProducts'] = '\n'.join(product_list)
    info['affectedCPEs'] = '\n'.join(cpe_list)

    return info


def main():

    # VARs
    year = '2022'
    nvd_api_key = ''
    report_summary = f'reports/vipvulns-summary_{year}.csv'
    report_detailed = f'reports/vipvulns-details_{year}.csv'

    # Retrieve all published CISA Alerts for the specified year and parse referenced CVEs
    data = scrape_cisa_alerts(year)

    # Convert to Dataframe
    df_summary = pd.DataFrame(data)

    # Split CVEs on separate rows individually
    df_detailed = df_summary.explode('cve')

    # Process only unique CVEs to avoid duplicate API requests
    df_cve = df_detailed[['cve']]
    df_cve = df_cve.drop_duplicates(subset='cve', keep="first").reset_index(drop=True)

    df_cve['cve'] = df_cve['cve'].fillna('')
    for i, row in df_cve.iterrows():
        if row['cve'] != '':
            print(f'\tRetrieving info for {row["cve"]}')
            cve_info = get_cve_details(row['cve'], nvd_api_key)

            # Add new attributes to the CVE details
            for key in cve_info.keys():
                df_cve.at[i, key] = cve_info[key]

    # Merge CVE data with Detailed CISA report
    df_detailed = pd.merge(df_detailed, df_cve, how='left', left_on='cve', right_on='cve')

    # Write reports
    df_summary.to_csv(report_summary, index=False)
    df_detailed.to_csv(report_detailed, index=False)


if __name__ == "__main__":
    main()
