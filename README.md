# Winter Sale Sleuth
### A bot for Steam's Winter 2015/2016 ARG 

A Python bot that queries every AppID on the steam store for given passwords the user enters.

## What you need to run
* Python
* PyCrypto
	* This is a C module and needs to be compiled before running.
	* `pip install pyCrypto` will download and install this but you'll probably get an error if you're not on Linux (`vcvarsall.bat missing` or a similar message)!
	* Windows users (like me) can also find binaries at http://www.voidspace.org.uk/python/modules.shtml#pycrypto
	* Download the binary and run the installer for your version of python. If yours it not there, you can google and probably find one for your version of python.
* Requests
	* `pip install requests` will download and install this package to your python install
	
## How to run
* As of now you have to configure everything in `wss_main.py` (Specifically there's a passwords array at the bottom to place all your passwords)
* After you add your passwords, call `python wss_main.py`
* Login if necessary, it's required to actually submit passwords and get a response (Supports SteamGuard, Captcha, but NOT TWO FACTOR (right now))
* It will begin to chug through all the passwords, logging things of interest