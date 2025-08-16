import gzip
import os
import sys
import xml.etree.ElementTree as ET
import zipfile
from datetime import datetime, timezone


def extract_xml_from_zip(zip_path):
    with zipfile.ZipFile(zip_path, "r") as z:
        xml_files = [f for f in z.namelist() if f.lower().endswith(".xml")]
        if not xml_files:
            print("No XML files found in the zip archive.")
            return []
        xml_contents = []
        for xml_file in xml_files:
            with z.open(xml_file) as f:
                xml_contents.append(f.read())
        return xml_contents


def extract_xml_from_gz(gz_path):
    with gzip.open(gz_path, "rb") as f:
        return [f.read()]


def parse_unix_timestamp(ts):
    try:
        return datetime.fromtimestamp(int(ts), tz=timezone.utc).strftime(
            "%Y-%m-%d %H:%M:%S UTC"
        )
    except Exception:
        return str(ts)


def parse_dmarc_xml(xml_content):
    tree = ET.ElementTree(ET.fromstring(xml_content))
    root = tree.getroot()
    if root is None:
        return "Error: XML root is None."
    ns = ""
    if root.tag.startswith("{"):
        ns = root.tag.split("}")[0] + "}"
    # Report metadata
    org_name = root.findtext(f".//{ns}org_name", default="")
    begin = root.findtext(f".//{ns}date_range/{ns}begin", default="")
    end = root.findtext(f".//{ns}date_range/{ns}end", default="")
    # Policy
    domain = root.findtext(f".//{ns}policy_published/{ns}domain", default="")
    p = root.findtext(f".//{ns}policy_published/{ns}p", default="")
    sp = root.findtext(f".//{ns}policy_published/{ns}sp", default="")
    pct = root.findtext(f".//{ns}policy_published/{ns}pct", default="")

    # Extract detailed records with all available authentication data
    records = []
    for record in root.findall(f".//{ns}record"):
        # Basic row data
        source_ip = record.findtext(f".//{ns}row/{ns}source_ip", default="")
        count = record.findtext(f".//{ns}row/{ns}count", default="")
        disposition = record.findtext(
            f".//{ns}row/{ns}policy_evaluated/{ns}disposition", default=""
        )
        dkim_result = record.findtext(
            f".//{ns}row/{ns}policy_evaluated/{ns}dkim", default=""
        )
        spf_result = record.findtext(
            f".//{ns}row/{ns}policy_evaluated/{ns}spf", default=""
        )

        # Detailed authentication results
        auth_results = record.find(f".//{ns}auth_results")
        spf_details = {}
        dkim_details = []

        if auth_results is not None:
            # SPF details
            spf_auth = auth_results.find(f".//{ns}spf")
            if spf_auth is not None:
                spf_details = {
                    "domain": spf_auth.findtext(f".//{ns}domain", default=""),
                    "result": spf_auth.findtext(f".//{ns}result", default=""),
                }

            # DKIM details (can have multiple)
            for dkim_auth in auth_results.findall(f".//{ns}dkim"):
                dkim_details.append(
                    {
                        "domain": dkim_auth.findtext(f".//{ns}domain", default=""),
                        "result": dkim_auth.findtext(f".//{ns}result", default=""),
                        "selector": dkim_auth.findtext(f".//{ns}selector", default=""),
                    }
                )

        records.append(
            {
                "source_ip": source_ip,
                "count": count,
                "disposition": disposition,
                "dkim": dkim_result,
                "spf": spf_result,
                "spf_details": spf_details,
                "dkim_details": dkim_details,
            }
        )

    # Calculate summary stats
    total_messages = sum(int(rec["count"]) for rec in records)
    failed_records = []
    warning_records = []
    success_count = 0

    for rec in records:
        passed_spf = rec["spf"] == "pass"
        passed_dkim = rec["dkim"] == "pass"

        if passed_spf and passed_dkim and rec["disposition"] in ("none", "pass"):
            success_count += int(rec["count"])
        elif (passed_spf or passed_dkim) and rec["disposition"] in (
            "none",
            "pass",
            "quarantine",
        ):
            warning_records.append(rec)
        else:
            failed_records.append(rec)

    # Build output - only show failures and warnings with summary
    output_lines = []

    # Report header
    output_lines.append(
        f"Report: {domain} | From: {org_name} | Period: {parse_unix_timestamp(begin)} to {parse_unix_timestamp(end)}"
    )
    output_lines.append(f"Policy: p={p}, sp={sp}, pct={pct}")
    output_lines.append("")

    # Show failures with detailed information
    if failed_records:
        output_lines.append("🚨 FAILURES - INVESTIGATE IMMEDIATELY 🚨")
        output_lines.append("=" * 60)

        for i, rec in enumerate(failed_records):
            count_str = "1 email" if rec["count"] == "1" else f"{rec['count']} emails"
            output_lines.append(
                f"\n❌ FAILURE #{i + 1}: {count_str} from IP {rec['source_ip']}"
            )
            output_lines.append(f"   Disposition: {rec['disposition'].upper()}")
            output_lines.append(
                f"   Policy Results: SPF={rec['spf'].upper()}, DKIM={rec['dkim'].upper()}"
            )

            # SPF details
            if rec["spf_details"]:
                output_lines.append(
                    f"   SPF Check: domain={rec['spf_details']['domain']}, result={rec['spf_details']['result']}"
                )

            # DKIM details
            if rec["dkim_details"]:
                for j, dkim in enumerate(rec["dkim_details"]):
                    selector_info = (
                        f", selector={dkim['selector']}" if dkim["selector"] else ""
                    )
                    output_lines.append(
                        f"   DKIM Check #{j + 1}: domain={dkim['domain']}, result={dkim['result']}{selector_info}"
                    )

            output_lines.append(
                "   → ACTION: Verify email authentication for this IP address"
            )

        output_lines.append("")

    # Show warnings with details
    if warning_records:
        output_lines.append("⚠️ WARNINGS - PARTIAL AUTHENTICATION")
        output_lines.append("-" * 40)

        for i, rec in enumerate(warning_records):
            count_str = "1 email" if rec["count"] == "1" else f"{rec['count']} emails"
            output_lines.append(
                f"\n⚠️ WARNING #{i + 1}: {count_str} from IP {rec['source_ip']}"
            )
            output_lines.append(
                f"   Policy Results: SPF={rec['spf'].upper()}, DKIM={rec['dkim'].upper()}"
            )

            if rec["spf_details"]:
                output_lines.append(
                    f"   SPF: domain={rec['spf_details']['domain']}, result={rec['spf_details']['result']}"
                )
            if rec["dkim_details"]:
                for dkim in rec["dkim_details"]:
                    output_lines.append(
                        f"   DKIM: domain={dkim['domain']}, result={dkim['result']}"
                    )

        output_lines.append("")

    # Summary line
    failed_count = sum(int(rec["count"]) for rec in failed_records)
    warning_count = sum(int(rec["count"]) for rec in warning_records)

    summary_parts = []
    if failed_count > 0:
        summary_parts.append(f"🚨 {failed_count} FAILED")
    if warning_count > 0:
        summary_parts.append(f"⚠️ {warning_count} WARNINGS")
    if success_count > 0:
        summary_parts.append(f"✅ {success_count} SUCCESS")

    output_lines.append(
        f"SUMMARY: {' | '.join(summary_parts)} | Total: {total_messages} messages"
    )

    # Only return output if there are failures or warnings
    if failed_records or warning_records:
        return "\n".join(output_lines)
    else:
        return f"\u2705 {domain} ({org_name}): All {total_messages} messages passed authentication"


def main():
    # Set UTF-8 encoding for Windows console output
    if sys.platform.startswith("win"):
        import codecs

        sys.stdout = codecs.getwriter("utf-8")(sys.stdout.buffer, "strict")

    reports = os.listdir("reports")
    for report in reports:
        path = os.path.join("reports", report)
        ext = os.path.splitext(path)[1].lower()
        if ext == ".zip":
            xmls = extract_xml_from_zip(path)
        elif ext == ".gz":
            xmls = extract_xml_from_gz(path)
        elif ext == ".xml":
            with open(path, "rb") as f:
                xmls = [f.read()]
        else:
            raise Exception(
                "Unsupported file type. Please provide a .zip, .gz, or .xml file."
            )
        for xml_content in xmls:
            summary = parse_dmarc_xml(xml_content)
            print(summary)


if __name__ == "__main__":
    main()
