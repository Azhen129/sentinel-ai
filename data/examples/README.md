These are hand-authored synthetic Zeek-format connection records using only RFC 5737 documentation address ranges. They contain no captured network data, identifying information, or real targets. They demonstrate parser compatibility, not any measured detection performance.

`conn.json` contains newline-delimited JSON; `conn.log` contains equivalent Zeek TSV with a `#fields` header. Import only in explicitly enabled authorized lab mode. The port 23 record triggers the unexpected-port review rule.
