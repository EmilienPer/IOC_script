# IOC and security issues scanner
## Description
This program aims to provide a way to scan and detect indicators of compromise and security issues via SSH connection.
It is based on open source tools "Loki IOC scanner" (<https://github.com/Neo23x0/Loki>) and "Lynis" (<https://github.com/CISOfy/lynis>). 
After giving SSH authentication information, the program sends a version of tools on the target and scans it. Logs are then aggregated into a single PDF or json report.
### Capabilities and Functionalities
- Linux target scan
- SSH connection (password or key file)
- Loki IOC scanner update
- Loki IOC scanner signature update
- OS detection (Linux/Windows)
- Report in PDF or json format
- Auto-update

Thanks to the use of Loki IOC scanner and Lynis, this program is able to execute the following task:
- File Name IOC Check (Regex match on full file path/name)
- Yara Rule Check (Yara signature match on file data and process memory)
- Hash Check (Compares known malicious hashes (MD5, SHA1, SHA256) with scanned files)
- C2 Back Connect Check (Compares process connection endpoints with C2 IOCs)
- Automated security auditing
- Compliance testing (e.g. ISO27001, PCI-DSS, HIPAA)
- Vulnerability detection

### Future releases capabilities/ functionalities
- Scan Windows Target: For the moment, the scan is only available on Linux target due to Lynis purpose. We are currently looking for a open source compatible scanner for windows to integrate into the program.
- Yara rules, File name and hash importation: Currently, the signature are based on the signature given by Loki IOC scanner. In a future version, we are going to include the possibility for the user to import his own rules
- Lynis update: Very soon, the Lynis update will be integrated into the program

## Requirements
- python 3
- pip
- internet access (to update and install requirements via pip)
- SSH

On the target: 
- python 3
- pip
- internet access (to install requirements via pip)
- SSH user with sudo right

## Installation
There are multiple options available to install this program
### From Git
The very latest developments can be obtained via git.
1. Clone or download the project files ;

        git clone https://github.com/EmilienPer/ioc_security_issue_scanner
2. Install requirements

       cd ioc_security_issue_scanner && pip install -r requirements.txt || pip3 install -r requirements.txt    
4. Execute:

       python3 ioc_security_issues_scanner.py

## Usage
There is two way to use this program 
### GUI
1. Start the application (after install all requirements)

       python3 ioc_security_issues_scanner.py
       
2. If a new version is available, we strongly advise you to update it

3. The main window appears :


 ![Main window](/images/main_window.png)
 
 
4. On the first use, update Loki (CTRL+L) and Loki signature (CTRL+U)

5. Complete authentication information


 ![authentication](/images/authentication.PNG)
 
 
6. Select scans you want to run


  ![scan](/images/scans.PNG)
  
  
7.  Select the output type and the path to the directory to use for the output


  ![output_selection](/images/output.PNG)
  
  
8. Start the scan. A  scan can take a long time (2-3h)

10. After authentication on the target, the name and the OS type are displayed on the GUI


  ![target](/images/target.PNG)
  
  
11. Wait for the end of scans (a popup message will appear at the end)

  ![done](/images/done.PNG)
  
12. The report is available on the output directory. You can also find lynis and loki report

### Command line
    usage: python3 ioc_security_issues_scanner.py [-h] [--update {all,program,loki,sign} | --scan TARGET] [-u USER] [-k KEY_FILE | -p PASSWORD] [--port PORT] [-t {PDF,JSON}] [-P PATH] [--noioc] [--noissue]    
        
    optional arguments:
      -h, --help            show this help message and exit
      --update {all,program,loki,sign}
                            Use this option to update an element of this program
      --scan TARGET         The target IP address
      -u USER, --user USER  The Target's SSH username
      -k KEY_FILE, --key_file KEY_FILE
                            Path to the private key for SSH authentication
      -p PASSWORD, --password PASSWORD
                            Password for SSH authentication
      --port PORT           The Target's SSH port
      -t {PDF,JSON}, --type {PDF,JSON}
                            The report type
      -P PATH, --path PATH  The report output directory
      --noioc               Do not scan for IOC
      --noissue             Do not scan for Security issues
      
#### Examples
Update program, loki and signatures
        
        python3 ioc_security_issues_scanner.py --update all

Update loki
            
        python3 ioc_security_issues_scanner.py --update loki

Run a scan on 127.0.0.1 with private key file and save report as PDF in tmp directory

        python ioc_security_issues_scanner.py --scan 127.0.0.1 -u user -k /path/to/the/private.key -t PDF -P tmp
        
Run a scan on 127.0.0.1 with  password but do not scan ioc

        python ioc_security_issues_scanner.py --scan 127.0.0.1 -u user -p the_password -t PDF -P tmp --noioc
     
## Contribute
Do you have something to share? Create an issue or pull request on GitHub. 

You can also simply contribute to the project by _starring_ the project and show your appreciation that way.

## License
IOC and security issues scanner

 Copyright (C) 2022 Emilien Peretti
 
This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.
This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
You should have received a copy of the GNU General Public License along with this program. If not, see http://www.gnu.org/licenses/
## Issues
### yara.SyntaxError: invalid field name "imphash"
This issues is due to yara-python on the target. 

To solve it, we found 2 solutions (tried on Ubuntu):
- 1. Install yara using the following documentation: https://yara.readthedocs.io/en/stable/gettingstarted.html#installing-with-vcpkg
  2. Install yara-python

        git clone --recursive https://github.com/VirusTotal/yara-python
        cd yara-python
        python setup.py build
        sudo python setup.py install
- install yara-python 4.1.0 (`pip install yara-python==4.1.0`)
