# Deploy Windows 10 Virtual Machine
Ever do a fresh install of Windows 10, only to see a bunch of bloatware like Candy Crush Saga?

This script was designed to configure a newly installed Windows 10 virtual machine for simplicity and privacy. It also installs Boxstarter, a deployment environment for Chocolatey. 

It also has a function to install required software if needed. This means you can host your own powershell script on the Internet (Github repo, gist, etc) and run it along with everything else.

## Usage
Open Powershell (run as an adminstrator) 

![PS as admin](./media/powershellasadmin.gif)

Run the following command:

` . { Invoke-WebRequest -useb URL } | Invoke-Expression; Deploy-NewWindows10`

To run this script with another software installation script, run the following command:

` . { Invoke-WebRequest -useb URL } | Invoke-Expression; Deploy-NewWindows10 -installPkg URLOFSCRIPT`

## Output
This script will create a transcript for troubleshooting purposes. This should be located in the users Documents directory. 