<!DOCTYPE html>
<html xmlns="http://www.w3.org/1999/xhtml" lang="" xml:lang="">
<head>
  <meta charset="utf-8" />
  <meta name="generator" content="pandoc" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0, user-scalable=yes" />
  <title>PowIRShell Documentation</title>
  <style>
    html {
      color: #1a1a1a;
      background-color: #fdfdfd;
    }
    body {
      margin: 0 auto;
      max-width: 36em;
      padding-left: 50px;
      padding-right: 50px;
      padding-top: 50px;
      padding-bottom: 50px;
      hyphens: auto;
      overflow-wrap: break-word;
      text-rendering: optimizeLegibility;
      font-kerning: normal;
    }
    @media (max-width: 600px) {
      body {
        font-size: 0.9em;
        padding: 12px;
      }
      h1 {
        font-size: 1.8em;
      }
    }
    @media print {
      html {
        background-color: white;
      }
      body {
        background-color: transparent;
        color: black;
        font-size: 12pt;
      }
      p, h2, h3 {
        orphans: 3;
        widows: 3;
      }
      h2, h3, h4 {
        page-break-after: avoid;
      }
    }
    p {
      margin: 1em 0;
    }
    a {
      color: #1a1a1a;
    }
    a:visited {
      color: #1a1a1a;
    }
    img {
      max-width: 100%;
    }
    svg {
      height: auto;
      max-width: 100%;
    }
    h1, h2, h3, h4, h5, h6 {
      margin-top: 1.4em;
    }
    h5, h6 {
      font-size: 1em;
      font-style: italic;
    }
    h6 {
      font-weight: normal;
    }
    ol, ul {
      padding-left: 1.7em;
      margin-top: 1em;
    }
    li > ol, li > ul {
      margin-top: 0;
    }
    blockquote {
      margin: 1em 0 1em 1.7em;
      padding-left: 1em;
      border-left: 2px solid #e6e6e6;
      color: #606060;
    }
    code {
      font-family: Menlo, Monaco, Consolas, 'Lucida Console', monospace;
      font-size: 85%;
      margin: 0;
      hyphens: manual;
    }
    pre {
      margin: 1em 0;
      overflow: auto;
    }
    pre code {
      padding: 0;
      overflow: visible;
      overflow-wrap: normal;
    }
    .sourceCode {
     background-color: transparent;
     overflow: visible;
    }
    hr {
      background-color: #1a1a1a;
      border: none;
      height: 1px;
      margin: 1em 0;
    }
    table {
      margin: 1em 0;
      border-collapse: collapse;
      width: 100%;
      overflow-x: auto;
      display: block;
      font-variant-numeric: lining-nums tabular-nums;
    }
    table caption {
      margin-bottom: 0.75em;
    }
    tbody {
      margin-top: 0.5em;
      border-top: 1px solid #1a1a1a;
      border-bottom: 1px solid #1a1a1a;
    }
    th {
      border-top: 1px solid #1a1a1a;
      padding: 0.25em 0.5em 0.25em 0.5em;
    }
    td {
      padding: 0.125em 0.5em 0.25em 0.5em;
    }
    header {
      margin-bottom: 4em;
      text-align: center;
    }
    #TOC li {
      list-style: none;
    }
    #TOC ul {
      padding-left: 1.3em;
    }
    #TOC > ul {
      padding-left: 0;
    }
    #TOC a:not(:hover) {
      text-decoration: none;
    }
    code{white-space: pre-wrap;}
    span.smallcaps{font-variant: small-caps;}
    div.columns{display: flex; gap: min(4vw, 1.5em);}
    div.column{flex: auto; overflow-x: auto;}
    div.hanging-indent{margin-left: 1.5em; text-indent: -1.5em;}
    /* The extra [class] is a hack that increases specificity enough to
       override a similar rule in reveal.js */
    ul.task-list[class]{list-style: none;}
    ul.task-list li input[type="checkbox"] {
      font-size: inherit;
      width: 0.8em;
      margin: 0 0.8em 0.2em -1.6em;
      vertical-align: middle;
    }
    .display.math{display: block; text-align: center; margin: 0.5rem auto;}
  </style>
</head>
<body>
<h1 id="powirshell">PowIRShell</h1>
<p>PowerShell scripts useful for incident response and Active Directory
auditing.</p>
<p>This is a collection of Powershell scripts which are useful for
information security tasks. Currently the main script
Get-M365CompromiseInfo. It takes Microsoft365 Unified Audit Log (UAL)
files in JSON format and looks up IP addresses using either IPInfo.io,
Scamalytics, IPQualityScore, or all three.</p>
<h2 id="quick-start">Quick start:</h2>
<pre><code>git clone https://github.com/kgeil/PowIRShell.git
Import-Module .\M365CompromiseInfo.psd1
Get-M365CompromiseInfo -searchdir C:\temp\365Comp\UAL -outputDir C:\temp\365Comp\ -ipinfoLookup -ipinfoAPIKey &#39;&lt;IpInfoKeyHere&gt;&#39; -ScamalyticsLookup -scamalyticsAPIKey &#39;&lt;ScamalyticsKeyHere&gt;&#39;</code></pre>
<p>The script will then start doing its work. A gridview will appear,
offering you the option of selecting IP addresses based on ASN, geo-ip
lookup, etc. If you pay for an IPQS license, this may not be necessary.
The grid allows you to weed out IP addresses to save time and money on
threat intel lookups.</p>
<p>The grid looks like this. Select your IPs, and click OK in the
gridview.</p>
<figure>
<img
src="https://github.com/kgeil/PowIRShell/assets/10849557/a8663036-3901-40df-9bfb-3123e3790fe4"
alt="image" />
<figcaption aria-hidden="true">image</figcaption>
</figure>
<p><strong>Caveat Emptor: The results of this script are only as good as
your IP threat intel lookups. If you fail to select an IP in the
gridview, it will not be checked! Also, if a malicious IP comes through
as non-malicious from scamalytics or IPQS, it will not be detected by
the script.</strong></p>
<h3 id="output">Output:</h3>
<p>The script will produce some log files, and two csv files:
MaliciousLogons.csv, and MaliciousMailItemsAccessed.csv. These files
contain event information for activities associated with malicious IPs
detected by threat intel services. <img
src="https://github.com/kgeil/PowIRShell/assets/10849557/af3ea276-50ec-48a9-94cb-9445d90e591a"
alt="image" /></p>
<h2 id="other-stuff">Other stuff:</h2>
<p>The script “PowerConTalk.ps1” is not really a script, but rather a
series of useful commands. The first section provides ideas for auditing
Active Directory, and the second section is a walkthrough of a business
email compromise investigation, using some of the scripts from this
repository.</p>
<h2 id="included-scripts">Included scripts:</h2>
<ul>
<li>Get-IPInfoLookup.ps1: Input: list of IP addresses separated by
newlines. Output: Geo-ip and ASN info for each IP. IPInfo’s API. API Key
required. Get it here: <em>https://ipinfo.io/</em></li>
<li>Get-IPQSLookup.ps1: Input: list of IP addresses separated by
newlines. Output: IP Quality Score’s threat intelligence information.
API Key required. Get it here:
<em>https://www.ipqualityscore.com/</em></li>
<li>Get-Scamalytics_lookup.ps1: Input: list of IP addresses separated by
newlines. Output: Scamalytics threat intelligence information. API Key
required. Get it here: <em>https://scamalytics.com/</em></li>
<li>Get-M365CompromiseInfo.ps1. Use PowerShell’s built-in help for
usage: Get-help &lt; path-to-script &gt; -ShowWindow</li>
<li>PowerConTalk.ps1 Used to provide a live demo of some useful
PowerShell techniques and some scripts from this repository.</li>
<li>Get-Artifacts.ps1: Parses evtx files and returns output usful in
incident response triage. Use PowerShell’s built-in help for usage:
Get-help &lt; path-to-script &gt; -ShowWindow.</li>
<li>Resolve-Hostnames.ps1: <em>A work in progress</em>. Takes a list of
hostnames and returns A and AAAA records.</li>
</ul>
</body>
</html>
