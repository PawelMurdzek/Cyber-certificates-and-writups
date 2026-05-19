# System Logs

## Linux Logs

Linux OS stores all the related logs, such as events, errors, warnings, etc. These are then ingested into SIEM for continuous monitoring. Some of the common locations where Linux stores logs are:

* `/var/log/apache2` or `/var/log/httpd`: Contains web server HTTP Request / Response and error logs.
* `/var/log/cron`: Events related to cron jobs are stored in this location.
* `/var/log/auth.log` and `/var/log/secure`: Stores authentication-related logs.
* `/var/log/kern`: This file stores kernel-related events.

## Windows Logs

Windows OS uses the Windows Event Log service to record system, security, and application events, which can also be ingested into a SIEM. Common log files and locations include:

* `C:\Windows\System32\winevt\Logs`: Default directory containing Windows Event Viewer logs in `.evtx` format.
* **Security** (`Security.evtx`): Contains records of logon attempts, privileges, and other security-related events.
* **System** (`System.evtx`): Contains events logged by the Windows operating system and its components.
* **Application** (`Application.evtx`): Contains events logged by applications and third-party programs.

## Log Ingestion

All these logs provide a wealth of information and can help identify security issues. Each SIEM solution has its own way of ingesting the logs. Some common methods used by these SIEM solutions are explained below:

* **Agent / Forwarder**: These SIEM solutions provide a lightweight tool called an agent (forwarder by Splunk) that gets installed on the Endpoint. It is configured to capture and send all the important logs to the SIEM server.
* **Syslog**: Syslog is a widely used protocol to collect data from various systems like web servers, databases, etc., and send real-time data to the centralized destination.
* **Manual Upload**: Some SIEM solutions, like Splunk, ELK, etc., allow users to ingest offline data for quick analysis. Once the data is ingested, it is normalized and made available for analysis.
* **Port-Forwarding**: SIEM solutions can also be configured to listen on a certain port, and then the endpoints forward the data to the SIEM instance on the listening port.

## SIEM Detection Rule Examples (Use-Cases)

By collecting and analyzing logs, SIEMs can trigger alerts based on specific logic. Below are some common examples of detection rules using Windows Event Logs:

* **Detecting `whoami` Command Execution**
  * **Rule:** If `Log Source` is `WinEventLog` AND `EventCode` is `4688` (Process Creation) AND `NewProcessName` contains `whoami`
  * **Action:** Trigger an alert: `WHOAMI command Execution DETECTED`

* **Detecting Event Log Clearing**
  * **Rule:** If `Log Source` is `WinEventLog` AND `EventID` is `104` (Log clear)
  * **Action:** Trigger an alert: `Event Log Cleared`
