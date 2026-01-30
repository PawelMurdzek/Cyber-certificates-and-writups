# SIEM & Log Analysis

## Splunk

### Basic Search Syntax (SPL)
```splunk
index=main sourcetype=access_combined status=404
| stats count by clientip
| sort - count
```

### Common Commands
- `index=*`: Search all indexes.
- `piping (|)`: Pass results to next command.
- `fields`: Keep/Remove fields (`| fields + user`, `| fields - host`).
- `rename`: Rename fields (`| rename clientip as IP`).
- `stats`: Aggregation (`| stats count`, `| stats avg(bytes)`).
- `table`: Create a table view (`| table Time, IP, URL`).
- `top / rare`: Find most/least common values.
- `rex`: Extract fields using Regex.

## ELK Stack (Elasticsearch, Logstash, Kibana)

### KQL (Kibana Query Language)
- **Exact match**: `status:200`
- **Text match**: `message:"failed login"`
- **Range**: `bytes > 1000`
- **Boolean**: `response:404 AND extension:php`
- **Wildcard**: `user:adm*`
- **Exist check**: `_exists_:user`

## YARA
Pattern matching for malware samples.

### Rule Structure
```yara
rule Suspicious_Strings {
    meta:
        description = "Detects sus strings"
        author = "BlueTeam"
    strings:
        $a = "cmd.exe" ascii
        $b = "powershell -enc" nocase
        $hex = { 4D 5Z 90 }
    condition:
        $hex at 0 and ($a or $b)
}
```

### Usage
`yara -r my_rules.yar /path/to/scan`
