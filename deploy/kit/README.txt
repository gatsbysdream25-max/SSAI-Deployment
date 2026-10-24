SwarmSentinel USB kit
=====================

What this is: everything needed to install SwarmSentinel on one Linux machine with no internet and nothing else on the network.

Needs on the target machine
  - Ubuntu or Debian (systemd), 64-bit Intel/AMD, with python3 and python3-venv
  - The same Python version the kit was built with (see PYTHON_VERSION; INSTALL.sh checks)
  - 4 CPU cores and 16 GB RAM are comfortable for two AI models; the models run one at a time, so verdicts take a minute or two each
  - About 12 GB of free disk if the kit contains AI models (look for the "ai" folder)

Install
  1. Plug in the stick and open a terminal in this folder.
  2. sudo ./INSTALL.sh --demo
  3. Open the dashboard address it prints and sign in with the one-time admin password (change it under Settings).
     --demo adds six clearly-labelled EXAMPLE findings so there is something to watch. Leave it off for a real installation.

What happens to your data
  Nothing leaves the machine. The AI models run on the machine itself (127.0.0.1) and no cloud service is used unless you add a key.
  The kit holds no keys, passwords or network details of anyone: it is built from committed code only.

Removing it
  sudo /opt/swarmsentinel/deploy/uninstall.sh   (it asks before deleting data)
