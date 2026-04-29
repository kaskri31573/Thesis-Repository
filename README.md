# Thesis-Repository
This is my repository for my BP in CyberSecurity IBR traffic analysis.

Here is a step by step guide on how to make the script work for your PCAP files.
  Step 1. Rename the PCAP file to all lower case letters of the 3 first letters in the month you want to parse data from. (Example: jan.cap.gz, feb.cap.gz)
  Step 2. Download Python.
  Step 3. Make sure your PCAP file is located in the same directory as the Python script.
  Step 4. Open Terminal and find the path to your Python Script and PCAP file.
  Step 5. Download dpkt using: pip install dpkt.
  Step 6. Run the script on the PCAP file with python in your terminal.
  Command: python pcap_to_csv.py --months jan, feb, mar, etc...
  
  Additional Info: You do not add .cap.gz after the name of the file.
  Ps. Don't forget the "s" at the end of --months like me -_-
