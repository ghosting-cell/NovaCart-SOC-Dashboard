import streamlit as st
import re
import json
import plotly.express as px
from collections import Counter

st.set_page_config(
    page_title="NovaCart SOC Dashboard",
    layout="wide"
)

st.markdown("""
<style>
.stApp {
    background-color: #0b1120;
    color: #e2e8f0;
}

section[data-testid="stSidebar"] {
    background-color: #111827;
}

h1, h2, h3 {
    color: #e2e8f0;
}

p, label {
    color: #cbd5e1;
}

div[data-testid="stMetric"] {
    background-color: #151f33;
    border: 1px solid #293752;
    padding: 18px;
    border-radius: 12px;
}

div[data-testid="stMetricLabel"] {
    color: #94a3b8;
}

div[data-testid="stMetricValue"] {
    color: #22d3ee;
}

div[data-testid="stDataFrame"] {
    border: 1px solid #293752;
    border-radius: 10px;
}

hr {
    border-color: #293752;
}
</style>
""", unsafe_allow_html=True)

st.title("🛡️ NovaCart SOC Dashboard")
st.caption("Security Operations Center | Live Security Monitoring")
st.divider()

log_file = "/var/log/novacart/security.log"

def read_logs():

    with open(log_file, "r") as file:
        return file.readlines()


def analyze_events(logs):

    events = []

    for line in logs:

        match = re.search(r"\]\s*\[([A-Z_]+)\]", line)

        if match:
            events.append(match.group(1))

    return Counter(events)
def analyze_ips(logs):

    ip_addresses = []

    for line in logs:

        match = re.search(r"IP=([0-9.]+)", line)

        if match:
           events.append(match.group(1))

    return Counter(events)
def analyze_ips(logs):

    ip_addresses = []

    for line in logs:

        match = re.search(r"IP=([0-9.]+)", line)

        if match:
            ip_addresses.append(match.group(1))

    return Counter(ip_addresses)

def analyze_log_details(logs):

    details = []

    for line in logs:

        timestamp = re.search(r"\[(.*?)\]", line)
        event = re.search(r"\]\s*\[([A-Z_]+)\]", line)
        ip = re.search(r"IP=([0-9.]+)", line)
        method = re.search(r"METHOD=(\S+)", line)
        endpoint = re.search(r"ENDPOINT=(\S+)", line)
        user = re.search(r"USER=(\S+)", line)
        message = re.search(r"DETAILS=(.*)", line)
if timestamp and event:

            details.append({
                "Timestamp": timestamp.group(1),
                "Event": event.group(1),
                "IP Address": ip.group(1) if ip else "N/A",
                "Method": method.group(1) if method else "N/A",
                "Endpoint": endpoint.group(1) if endpoint else "N/A",
                "User": user.group(1) if user else "N/A",
                "Details": message.group(1).strip() if message else "N/A"
            })

    return details


@st.fragment(run_every="5s")
def live_dashboard():
    try:
        logs = read_logs()
        event_counts = analyze_events(logs)
        ip_counts = analyze_ips(logs)
        log_details = analyze_log_details(logs)

        st.success("Connected to NovaCart security logs!")

        st.markdown("## Security Overview")
        st.caption("Real-time summary of NovaCart security activity")

col1, col2, col3, col4 = st.columns(4, gap="medium")

        col1.metric("Total Events", len(logs))
        col2.metric("Login Success", event_counts["LOGIN_SUCCESS"])
        col3.metric("Login Failures", event_counts["LOGIN_FAILURE"])
        col4.metric("Unknown Users", event_counts["UNKNOWN_USER"])
        st.subheader("Security Event Distribution")

        if event_counts:
            pie_data = {
                "Event": list(event_counts.keys()),
                "Count": list(event_counts.values())
            }

            fig = px.pie(
                pie_data,
                names="Event",
                values="Count",
                hole=0.35,
                title="Security Event Distribution"
            )

            fig.update_layout(
                template="plotly_dark",
                paper_bgcolor="#0b1120",
                font_color="#e2e8f0"
            )

            st.plotly_chart(fig, use_container_width=True)
           else:
            st.info("No security events available.")
            st.info("No security events available.")
        st.markdown("## 🚨 Recent Security Alerts")
        st.caption("Detected suspicious login activity and security events")

        alert_file = "/root/novacart-soc/alerts.jsonl"

        try:
            with open(alert_file, "r") as file:
                alert_lines = file.readlines()

            if alert_lines:
                for line in reversed(alert_lines):
                    alert = json.loads(line)

                    with st.container(border=True):
                        severity = alert["severity"]

                        if severity == "HIGH":
                            st.error("🔴 HIGH SEVERITY")
                        elif severity == "MEDIUM":
                            st.warning("🟠 MEDIUM SEVERITY")
                        else:
                            st.info("🔵 LOW SEVERITY")

                        col1, col2, col3 = st.columns(3)

                        col1.write("**Event**")
                      col1.write(alert["event"])

                        col2.write("**IP Address**")
                        col2.write(alert["ip"])

                        col3.write("**Attempts**")
                        col3.write(alert["attempts_in_window"])
            else:
                st.info("No security alerts found.")


        except FileNotFoundError:
            st.warning("Alert file not found.")

        st.markdown("## 🌐 IP Address Monitoring")
        st.caption("Monitor source IP addresses and their total security eve>

        if ip_counts:
            ip_table = {
                "IP Address": list(ip_counts.keys()),
                "Total Events": list(ip_counts.values())
            }

            st.dataframe(ip_table, use_container_width=True)

        else:
            st.info("No IP addresses found.")
        st.markdown("## 📋 Security Event Details")
        st.caption("Detailed records of authentication and security activity>

        if log_details:
            st.dataframe(
                log_details,
                use_container_width=True,
                hide_index=True
            )
        else:
            st.info("No security events found.")

    except FileNotFoundError:
        st.error("Security log file not found!")

    except PermissionError:
        st.error("Permission denied while reading security logs!")
live_dashboard()



