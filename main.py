# import dependencies
import base64
import os
from pywidevine import PSSH
from pywidevine import Cdm
from pywidevine import Device
import requests
import glob
import license_curl

# Get the current working directory
main_directory = os.getcwd()

# Making sure a .wvd file exists and using that as the extracted device
try:
    extracted_device = glob.glob(f'{main_directory}\\*.wvd')[0]
except:
    extracted_cdm = None
    print(f"Please place a WVD in {main_directory}\\")


# Defining decrypt function
def decrypt_content(pssh: str = None, license_url: str = None):
    # prepare pssh
    pssh = PSSH(pssh)

    # load device
    device = Device.load(extracted_device)

    # load CDM from device
    cdm = Cdm.from_device(device)

    # open CDM session
    session_id = cdm.open()

    challenge = cdm.get_license_challenge(session_id, pssh)
    license_curl.json_data["licenseChallenge"] = base64.b64encode(challenge).decode()

    # send license challenge
    licence = requests.post(
        url=license_url,
        headers=license_curl.headers,
        json=license_curl.json_data
    )

    if licence.status_code != 200:
        print(licence.content)
        return "Could not complete license challenge"
    licence = licence.json()["licenseData"]
    licence = str(licence)

    # parse license challenge
    cdm.parse_license(session_id, licence)

    # assign variable for returned keys
    returned_keys = ""
    for key in cdm.get_keys(session_id):
        if key.type != "SIGNING":
            returned_keys += f"{key.kid.hex}:{key.key.hex()}\n"

    # close session, disposes of session data
    cdm.close(session_id)

    return returned_keys

input_pssh = input(f"PSSH: \n")
lic_url = input(f"License URL: \n")

print(f"Keys:")
print(decrypt_content(pssh=input_pssh, license_url=lic_url))