[![License: AGPL v3](https://img.shields.io/badge/License-AGPL_v3-blue.svg)](https://www.gnu.org/licenses/agpl-3.0)[![v1.0.0-alpha](https://img.shields.io/badge/release-v1.0.0--alpha-yellow)](https://github.com/hhruszka/secretshunter/releases)
# secretshunter

secretshunter is a penetration testing tool that uses regular expressions to searche a filesystem for secrets. It can be used to search also container images for secrets by pointing to a containr's root filesystem.
It uses regular expressions provided in yaml files to find secrets (passwords, hashes, API keys etc.) in found plaintext files. 
It is compatible with yaml files provided by https://github.com/mazen160/secrets-patterns-db project.

secretshunter is multithreaded application that allows to control its impact on the system. It can be done by specifying the number of vCPUs it is allowed to use with option `-c` and 
also by throttling it based on maximum CPU usage set with option `-t`.   

## Usage
```
Usage: secretshunter.exe [OPTIONS] "space seperated directories to scan"
  -c int
        maximum number of vCPUs to be used by a program - optional (default 16)
  -h    prints help
  -t float
        throttling, range from 10 to 80 denoting maximum CPU usage (%) that the
        system cannot exceed during execution of the program - optional (default 80)
  -o string
        output file - optional (default "Stdout")
  -p string
        file with patterns - mandatory. Patterns can be found on https://github.com/mazen160/secrets-patterns-db
  -v    prints version information
  -x string
        comma seperated list of directories to exclude during the scan
```
## Licensing
secretshunter is licensed under the GNU Affero General Public License v3.0 (AGPLv3). You 
are free to use, distribute, and modify this software under the terms of the AGPLv3. If you 
modify this software, any changes or improvements made must be made available to the 
community under the same license. This license also applies to any software that uses or is 
derived from this software. Please refer to the full text of the AGPLv3 for more details: 
https://www.gnu.org/licenses/agpl-3.0.html

secretshunter includes third-party packages that are subject to their respective licenses:
- github.com/gabriel-vasile/mimetype is licensed under the MIT License. See https://github.com/gabriel-vasile/mimetype/blob/master/LICENSE for details.
- gobyexample.com/rate-limiting is licensed under the CC BY 3.0.See https://github.com/mmcgrana/gobyexample#license.
- github.com/dlclark/regexp2 is licensed under the Apache License, Version 2.0. See https://github.com/dlclark/regexp2/blob/master/LICENSE for details.
Please review these licenses before using this code or these packages in your own projects.
