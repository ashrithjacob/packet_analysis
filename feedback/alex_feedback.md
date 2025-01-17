Hi Ashrith. I got feedback from the WiFI network engineer:


Below is the tshark command to get most of the the AVP of access request.
tshark -r wifi-AI/RoamingIQRadiusfiltered.pcapng -Y radius -T fields -E separator=, -E quote=d -e radius.code -e radius.id -e radius.length -e radius.authenticator -e radius.User_Name -e radius.User_Password_encrypted -e radius.NAS_IP_Address -e radius.NAS_Identifier -e radius.Called_Station_Id -e radius.NAS_Port_Type -e radius.avp.vendor_id -e radius.Unknown_Attribute -e radius.Unknown_Attribute -e radius.Calling_Station_Id -e radius.Connect_Info -e radius.Unknown_Attribute -e radius.avp.vendor_id -e radius.Unknown_Attribute -e radius.avp.vendor_id -e radius.Unknown_Attribute -e radius.Message_Authenticator >> wifi-AI/vik_out.csv

----------------------------------------------------------------------------------------

I spoke to the network engineer. There is way too much data in these PCAPs to extract everything.

So I propose we get our system to dynamically create a list of TShark commands based on the customer's questions, and then get the system to execute those Tshark commands in order to get the right data to input into the AI. Is that possible?
----------------------------------------------------------------------------------------
Please see the examples of prompt (for prompt engineering) the AI to produce the right Tshark commands in order to parse the right data. Could we do this?

What details are included in the RADIUS Access-Request packets?

tshark -r wifi-AI/RoamingIQRadiusfiltered.pcapng -Y "radius.code == 1" -T fields -E separator=, -E quote=d -e radius.User_Name -e radius.Calling_Station_Id -e radius.Called_Station_Id -e radius.NAS_IP_Address -e radius.NAS_Identifier -e radius.Message_Authenticator

Which client devices failed to authenticate successfully?

tshark -r wifi-AI/RoamingIQRadiusfiltered.pcapng -Y "radius && !(radius.code == 2)" -T fields -E separator=, -E quote=d -e radius.User_Name -e radius.Calling_Station_Id -e radius.NAS_IP_Address

What is the average size of RADIUS packets exchanged in the capture?

tshark -r wifi-AI/RoamingIQRadiusfiltered.pcapng -Y "radius" -T fields -E separator=, -E quote=d -e frame.len

How many RADIUS packets are sent from each NAS IP address?

tshark -r wifi-AI/RoamingIQRadiusfiltered.pcapng -Y "radius" -T fields -E separator=, -E quote=d -e radius.NAS_IP_Address | sort | uniq -c

What vendor-specific attributes (AVPs) are included in the RADIUS packets?

tshark -r wifi-AI/RoamingIQRadiusfiltered.pcapng -Y "radius.avp.vendor_id" -T fields -E separator=, -E quote=d -e radius.avp.vendor_id -e radius.Unknown_Attribute

What are the unique NAS identifiers seen in the RADIUS packets?

tshark -r wifi-AI/RoamingIQRadiusfiltered.pcapng -Y "radius.NAS_Identifier" -T fields -E separator=, -E quote=d -e radius.NAS_Identifier | sort | uniq

Are there any unknown attributes in the RADIUS packets?

tshark -r wifi-AI/RoamingIQRadiusfiltered.pcapng -Y "radius.Unknown_Attribute" -T fields -E separator=, -E quote=d -e radius.Unknown_Attribute

Which RADIUS packets do not contain a Message-Authenticator?

tshark -r wifi-AI/RoamingIQRadiusfiltered.pcapng -Y "radius && !radius.Message_Authenticator" -T fields -E separator=, -E quote=d -e radius.code -e radius.User_Name -e radius.Calling_Station_Id

What is the sequence of RADIUS packets exchanged between a specific client and NAS?

tshark -r wifi-AI/RoamingIQRadiusfiltered.pcapng -Y "radius" -T fields -E separator=, -E quote=d -e radius.code -e radius.User_Name -e radius.Calling_Station_Id -e radius.NAS_IP_Address -e radius.Message_Authenticator

Which access points (Called-Station-Id) are used for each authentication attempt?

tshark -r wifi-AI/RoamingIQRadiusfiltered.pcapng -Y "radius" -T fields -E separator=, -E quote=d -e radius.Called_Station_Id -e radius.User_Name -e radius.Calling_Station_Id

So here is my proposed flow for our PCAP copilot:

1. Get the AI to figure out the right Tshark commands based on the user query ->
2. Extra the right data from Tshark based on the commands produced by the AI in step 1 ->
3. Get the AI to do the analysis of the PCAPs in natural language (including follow up questions) based on the extracted data in step 2.

Tuesday, Dec 31, 2024
lease see the examples of prompt (for prompt engineering) the AI to produce the right Tshark commands in order to parse the right data. Could we do this?

What details are included in the RADIUS Access-Request packets?

tshark -r wifi-AI/RoamingIQRadiusfiltered.pcapng -Y "radius.code == 1" -T fields -E separator=, -E quote=d -e radius.User_Name -e radius.Calling_Station_Id -e radius.Called_Station_Id -e radius.NAS_IP_Address -e radius.NAS_Identifier -e radius.Message_Authenticator


Which client devices failed to authenticate successfully?

tshark -r wifi-AI/RoamingIQRadiusfiltered.pcapng -Y "radius && !(radius.code == 2)" -T fields -E separator=, -E quote=d -e radius.User_Name -e radius.Calling_Station_Id -e radius.NAS_IP_Address



What is the average size of RADIUS packets exchanged in the capture?



tshark -r wifi-AI/RoamingIQRadiusfiltered.pcapng -Y "radius" -T fields -E separator=, -E quote=d -e frame.len



How many RADIUS packets are sent from each NAS IP address?



tshark -r wifi-AI/RoamingIQRadiusfiltered.pcapng -Y "radius" -T fields -E separator=, -E quote=d -e radius.NAS_IP_Address | sort | uniq -c



What vendor-specific attributes (AVPs) are included in the RADIUS packets?



tshark -r wifi-AI/RoamingIQRadiusfiltered.pcapng -Y "radius.avp.vendor_id" -T fields -E separator=, -E quote=d -e radius.avp.vendor_id -e radius.Unknown_Attribute



What are the unique NAS identifiers seen in the RADIUS packets?



tshark -r wifi-AI/RoamingIQRadiusfiltered.pcapng -Y "radius.NAS_Identifier" -T fields -E separator=, -E quote=d -e radius.NAS_Identifier | sort | uniq



Are there any unknown attributes in the RADIUS packets?



tshark -r wifi-AI/RoamingIQRadiusfiltered.pcapng -Y "radius.Unknown_Attribute" -T fields -E separator=, -E quote=d -e radius.Unknown_Attribute



Which RADIUS packets do not contain a Message-Authenticator?



tshark -r wifi-AI/RoamingIQRadiusfiltered.pcapng -Y "radius && !radius.Message_Authenticator" -T fields -E separator=, -E quote=d -e radius.code -e radius.User_Name -e radius.Calling_Station_Id



What is the sequence of RADIUS packets exchanged between a specific client and NAS?



tshark -r wifi-AI/RoamingIQRadiusfiltered.pcapng -Y "radius" -T fields -E separator=, -E quote=d -e radius.code -e radius.User_Name -e radius.Calling_Station_Id -e radius.NAS_IP_Address -e radius.Message_Authenticator



Which access points (Called-Station-Id) are used for each authentication attempt?



tshark -r wifi-AI/RoamingIQRadiusfiltered.pcapng -Y "radius" -T fields -E separator=, -E quote=d -e radius.Called_Station_Id -e radius.User_Name -e radius.Calling_Station_Id

So here is my proposed flow for our PCAP copilot:



1. Get the AI to figure out the right Tshark commands based on the user query ->
2. Extra the right data from Tshark based on the commands produced by the AI in step 1 ->
3. Get the AI to do the analysis of the PCAPs in natural language (including follow up questions) based on the extracted data in step 2.

----------------------------------------------------------------------------------------
Also, please add thsi to our prompt engineering. I would like to exclude http://udp.data and http://tcp.data unless the user asks for it specificially (since it generates a lot of raw hex data) - this is for point number 1:



When to Exclude HEX Fields (http://udp.data and http://tcp.data):
The user mentions "metadata," "general analysis," "patterns," "troubleshooting," or "exclude payload."
Example Prompts:
"Analyze patterns in network traffic."
"List all DNS queries."
"Extract RADIUS attributes."
"Show communication flows."
"Focus on metadata."



When to Include HEX Fields (http://udp.data and http://tcp.data):
The user mentions "raw data," "payload inspection," "custom protocol," or "deep packet analysis."
Example Prompts:
"Analyze custom AVPs in RADIUS packets."
"Decode and extract raw HTTP payloads."
"Inspect the full contents of TCP streams."



AI Generated Tshark Command:
tshark -r file.pcapng -Y radius -T fields -E separator=, -E quote=d \
-e radius.code -e radius.User_Name -e radius.Calling_Station_Id -e radius.Called_Station_Id

The hex fields are long and not be in the output normally, we may actually already have a prompt for this.

----------------------------------------------------------------------------------------

Ashrith, I created these prompts based on our core system prompts, which works really well with chatGPT. We do have an agentic workflow though with our core system using langchain, so unsure if that will be needed for our PCAP copilot or not, but for now, perhaps prompt engineering will be enough. ChapGPT works well, Llama does not work for us on the core system (Llama seems weak, even the new models, we also may need to re-prompt engineer it, but for now we have it working well with ChatGPT). Please let me know your thoughts on this.-> 
`PCAP_Copilot_prompts.txt`



Also, how does the Tshark currently work? You statically provided it with data it should extract, and then it converts it into a Panda's Dataframe? Then what happens, it gets converted to a CSV? (this of course needs to be done dynamically now, since we realize doing it statically will not provide us with the right fields).

I also created a second version, this one is even more in depth with more examples. Please try the first one first, and then we can try this second one if its still not good.-> `PCAP Copilot Prompts 2.txt`

3RD VERSION -> `PCAP Copilot Prompts 3.txt`

----------------------------------------------------------------------------------------

Step 1: Parse
[User Uploads PCAP(s) + Provides Initial Query]
↓
[LLM Generates Tshark Command + Parse PCAP(s)]
↓
[Output Structured Data in CSV/DataFrame]



Step 2: Analyze
[LLM Analyzes Output Data + Present Results in Natural Language/Visualizations]



Step 3: Follow-Up
[User Follow-Up Query]
↓
(a) LLM Determines Query Relates to Existing Data:
→ Analyzes Existing Data
→ Presents Results
(b) LLM Determines Query Requires New Parsing:
→ Generates New Tshark Command(s)
→ Parses PCAP(s) Again
→ Updates Data + Analyzes Data + Presents Results



*ALTERNATIVE STEP 3 (if we always assume we need new parsing):



Step 3: Follow-Up
[User Follow-Up Query]
↓
Always Assume New Parsing:
→ Generate New Tshark Command
→ Parse PCAP(s) Again
→ Update Data + Analyze Data + Present Results

----------------------------------------------------------------------------------------