<h1 align="center"> Deauthenticator </h1>
<h4 align="center"> A script to perform the Deauthentication attack </h4>



<br><br>


## Dependencies
- **This code only works on Linux.**
- Python 3.10 or higher **(No external lib is necessary)**


<br>


## Installation
No installation is necessary. Just download and run the script.
```bash
# Clone this repo (or download the script)
git clone https://github.com/olivercalazans/deauth.git

# Change to the directory
cd deauth

# Give execution permission, if necessary
chmod +x deauth.py
```


<br>


## How to use
```bash
# Example
sudo python3 deauth.py -i wlp2s0 -t 11:22:33:44:55:66 -b 66:55:44:33:22:11
```
> [!WARNING]
> You need to set the channel and change the interface mode to monitor mode **MANUALLY**.


<br>


## Legal and ethical use warning
> [!CAUTION] 
> 
> **YOU AGREE TO:**
> 1. Use only with **proper authorization**
> 2. Comply with **all applicable laws**
> 3. Assume **full liability** for misuse
> 
> **The Developer assume NO liability.**



<br>

## License
This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.
