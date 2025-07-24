import sys
import os
import zipfile
import gzip
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
import subprocess


def extract_xml_from_zip(zip_path):
    with zipfile.ZipFile(zip_path, 'r') as z:
        xml_files = [f for f in z.namelist() if f.lower().endswith('.xml')]
        if not xml_files:
            print('No XML files found in the zip archive.')
            return []
        xml_contents = []
        for xml_file in xml_files:
            with z.open(xml_file) as f:
                xml_contents.append(f.read())
        return xml_contents

def extract_xml_from_gz(gz_path):
    with gzip.open(gz_path, 'rb') as f:
        return [f.read()]

def parse_unix_timestamp(ts):
    try:
        return datetime.fromtimestamp(int(ts), tz=timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')
    except Exception:
        return str(ts)

def format_record(rec, org_name):
    count = rec['count']
    ip = rec['source_ip']
    dkim = rec['dkim']
    spf = rec['spf']
    disposition = rec['disposition']
    count_str = f"One (1) email" if count == '1' else f"{count} emails"
    base = f"{count_str} was sent from IP {ip}\n"
    # Status logic
    passed_spf = spf == 'pass'
    passed_dkim = dkim == 'pass'
    # Determine status and message
    if passed_spf and passed_dkim and disposition in ('none', 'pass'):
        # Success
        status = "✅ Successful Delivery"
        details = (
            f"✅ Passed SPF\n"
            f"✅ Passed DKIM checks\n"
            f"✅ No delivery issues\n"
            f"{org_name} fully accepted and processed the message in line with your DMARC policy."
        )
    elif (passed_spf or passed_dkim) and disposition in ('none', 'pass', 'quarantine'):
        # Partial pass
        status = "⚠️ Warning (Partial Pass)"
        details = (
            f"{'✅' if passed_spf else '❌'} Passed SPF\n"
            f"{'✅' if passed_dkim else '❌'} Passed DKIM checks\n"
            f"⚠️ Delivered, but not fully authenticated\n"
            f"{org_name} delivered the message, but {'DKIM' if not passed_dkim else 'SPF'} failed. You may want to verify your {'DKIM' if not passed_dkim else 'SPF'} setup."
        )
    else:
        # Failure
        status = "❌ Failure"
        details = (
            f"{'✅' if passed_spf else '❌'} Passed SPF\n"
            f"{'✅' if passed_dkim else '❌'} Passed DKIM checks\n"
            f"🚫 Blocked or sent to spam\n"
            f"{org_name} rejected or quarantined the message based on your DMARC policy."
        )
    return f"{status}\n\n{base}{details}"

def parse_dmarc_xml(xml_content):
    try:
        tree = ET.ElementTree(ET.fromstring(xml_content))
        root = tree.getroot()
        if root is None:
            return 'Error: XML root is None.'
        ns = ''
        if root.tag.startswith('{'):
            ns = root.tag.split('}')[0] + '}'
        # Report metadata
        org_name = root.findtext(f'.//{ns}org_name', default='')
        report_id = root.findtext(f'.//{ns}report_id', default='')
        begin = root.findtext(f'.//{ns}date_range/{ns}begin', default='')
        end = root.findtext(f'.//{ns}date_range/{ns}end', default='')
        # Policy
        domain = root.findtext(f'.//{ns}policy_published/{ns}domain', default='')
        p = root.findtext(f'.//{ns}policy_published/{ns}p', default='')
        sp = root.findtext(f'.//{ns}policy_published/{ns}sp', default='')
        pct = root.findtext(f'.//{ns}policy_published/{ns}pct', default='')
        # Records
        records = []
        for record in root.findall(f'.//{ns}record'):
            source_ip = record.findtext(f'.//{ns}row/{ns}source_ip', default='')
            count = record.findtext(f'.//{ns}row/{ns}count', default='')
            disposition = record.findtext(f'.//{ns}row/{ns}policy_evaluated/{ns}disposition', default='')
            dkim = record.findtext(f'.//{ns}row/{ns}policy_evaluated/{ns}dkim', default='')
            spf = record.findtext(f'.//{ns}row/{ns}policy_evaluated/{ns}spf', default='')
            records.append({
                'source_ip': source_ip,
                'count': count,
                'disposition': disposition,
                'dkim': dkim,
                'spf': spf
            })
        # Build summary
        summary_lines = []
        summary_lines.append(f"Report for: {domain}\nFrom: {org_name}\nPolicy: p={p}, sp={sp}, pct={pct}\nReport Period: {parse_unix_timestamp(begin)} to {parse_unix_timestamp(end)}\n\n")
        for i, rec in enumerate(records):
            summary_lines.append(format_record(rec, org_name))
            if i < len(records) - 1:
                summary_lines.append('\n\u23bb\n')  # Unicode for ⸻
        return '\n'.join(summary_lines)
    except Exception as e:
        return f'Error parsing XML: {e}'

def show_dialog(summary):
    # Escape double quotes and backslashes for AppleScript
    safe_summary = summary.replace('"', '\"').replace('\\', '\\\\')
    # AppleScript command
    script = f'display dialog "{safe_summary}" with title "DMARC Report Summary" buttons ["OK"] default button "OK"'
    try:
        subprocess.run(['osascript', '-e', script])
    except Exception as e:
        print(f'Error showing dialog: {e}')

def main():
    if len(sys.argv) != 2:
        print('Usage: python dmarc_report_parser.py <report.zip|report.gz|report.xml>')
        sys.exit(1)
    path = sys.argv[1]
    if not os.path.isfile(path):
        print(f'File not found: {path}')
        sys.exit(1)
    ext = os.path.splitext(path)[1].lower()
    if ext == '.zip':
        xmls = extract_xml_from_zip(path)
    elif ext == '.gz':
        xmls = extract_xml_from_gz(path)
    elif ext == '.xml':
        with open(path, 'rb') as f:
            xmls = [f.read()]
    else:
        print('Unsupported file type. Please provide a .zip, .gz, or .xml file.')
        sys.exit(1)
    for xml_content in xmls:
        summary = parse_dmarc_xml(xml_content)
        print(summary)
        show_dialog(summary)

if __name__ == '__main__':
    main() 