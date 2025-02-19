# ASN Data Collector
### v1.1.0
### Robert Li

A Python script for collecting and analyzing network routing data from multiple sources including RIPE RIS, Team Cymru, and various RIR APIs.

## Features

- Collects ASN and routing information from multiple authoritative sources:
  - Team Cymru
  - RIPE NCC
  - LACNIC
  - APNIC
  - AFRINIC
  - ARIN
  - WHOIS
- Supports bulk IP processing
- Rate-limited API calls
- Detailed and summary CSV outputs
- Missing ASN detection and correction
- Progress tracking with checkpoint recovery
- Fallback logic between data sources


## Installation

1. Create a virtual environment:
```bash
python -m venv env
source env/bin/activate  # On Windows use: env\Scripts\activate
```

## Install dependencies:

```bash
pip install -r requirements.txt
```

## Usage

Basic usage:

```bash
python ripe-ris-collector.py
```

Check and update missing ASN information:

```bash
python ripe-ris-collector.py --check-missing
```

Resume from checkpoint:

```bash
python ripe-ris-collector.py --checkpoint
```

Increase verbosity to include error messages:

```bash
python ripe-ris-collector.py --verbose
```

## Input Format

The script expects an input file (this can be specified inside the python script) with IP addresses in any format. It will extract valid IPs from each line.

## Output

Terminal output example:

```bash
Starting global network data collection for 12 unique subnets
[1/12] Processing subnet: 168.227.0.0/16
  → Found data via Team Cymru
  → Found ASN: 10299
  → Retrieved ASN details: "EMPRESAS MUNICIPALES DE CALI E.I.C.E. E.S.P., CO"
[2/12] Processing subnet: 168.232.0.0/16
  → Found data via Team Cymru
  → Found ASN: 264923
  → Retrieved ASN details: "Junior e Bruno Pecas e Servicos em Informatica ltd, BR"
[...]
```

The script generates two CSV files:

- A summary file with subnet information:

```csv
subnet,asn,asn_desc,country,count
168.227.0.0/16,10299,"""EMPRESAS MUNICIPALES DE CALI E.I.C.E. E.S.P., CO""",CO,1
168.232.0.0/16,264923,"""Junior e Bruno Pecas e Servicos em Informatica ltd, BR""",BR,1
```

- A detailed file with per-IP information and an output of the original source line:

```csv
original_line,subnet,asn,asn_desc,country
1 45.164.77.202,45.164.0.0/16,268592,"M A Conexao Eletrotecnica Multimidia Ltda ME, BR",BR
1 200.236.250.247,200.236.0.0/16,10881,"FUNPAR - Fundacao da UFPR para o DCTC, BR",BR
```

### License

MIT License

Copyright (c) 2025

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

