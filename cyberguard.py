import streamlit as st
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
from langchain_community.document_loaders import PyPDFLoader
from langchain.text_splitter import RecursiveCharacterTextSplitter
from langchain_community.vectorstores import FAISS
from langchain_huggingface import HuggingFaceEmbeddings
from langchain_community.document_loaders import PyPDFDirectoryLoader
from langchain_community.document_loaders import DirectoryLoader
from langchain.prompts import PromptTemplate
from langchain.chains import RetrievalQA
import sentence_transformers
from langchain import hub
from langchain.chains.combine_documents import create_stuff_documents_chain
from langchain_core.runnables import RunnableParallel, RunnablePassthrough
from langchain_core.output_parsers import StrOutputParser
from st_social_media_links import SocialMediaIcons
from datetime import datetime
from langchain_groq import ChatGroq

from dotenv import load_dotenv
# Load environment variables
load_dotenv()
import requests
import json
import sys
import os
import colorama
from time import sleep 

##############################################################################################################################################################
st.title("CYBER-GUARD")

#loader=PyPDFDirectoryLoader("./knowledgebase_for_chatbot/")
#data = loader.load()
#split the extracted data into text chunks using the text_splitter, which splits the text based on the specified number of characters and overlap
#text_splitter = RecursiveCharacterTextSplitter(chunk_size=1000, chunk_overlap=200)
#text_chunks = text_splitter.split_documents(data)
#download the embeddings to use to represent text chunks in a vector space, using the pre-trained model "sentence-transformers/all-MiniLM-L6-v2"
#embeddings = HuggingFaceEmbeddings(model_name="sentence-transformers/all-MiniLM-L6-v2")
# create embeddings for each text chunk using the FAISS class, which creates a vector index using FAISS and allows efficient searches between vectors
#vector_store = FAISS.from_documents(text_chunks, embedding=embeddings)

#vector_store.save_local("faiss_index")

#new_vector_store = FAISS.load_local(
 #    "faiss_index", embeddings, allow_dangerous_deserialization=True
 #)



# # Retrieve and generate using the relevant snippets of the blog.
#retriever = new_vector_store.as_retriever()

# from langchain_groq import ChatGroq
GROQ_API_KEY=os.getenv("GROQ_API_KEY")
llm = ChatGroq(
     temperature=0,
     model="llama-3.3-70b-versatile",
     api_key=GROQ_API_KEY
 )

 #prompt = hub.pull("rlm/rag-prompt")




#def format_docs(docs):
#     return "\n\n".join(doc.page_content for doc in docs)


#rag_chain = (
#     {"context": retriever | format_docs, "question": RunnablePassthrough()}
#     | prompt
#     | llm
#     | StrOutputParser()
# )





def get_sm_footprints_prompt(query):
    prompt=f"""
    You are a cybersecurity and data privacy expert specializing in social media safety. Your role is to guide users in protecting their digital presence. When interacting with users:  

    1. Provide detailed, step-by-step instructions on how to remove their footprints from specific social media platforms.  
    2. Offer best practices for safeguarding their personal data on social media, including account settings, password management, and recognizing potential risks.  
    3. Educate users on data privacy laws, their rights, and how these apply to social media usage.  
    4. Recommend actionable steps to minimize data sharing while ensuring compliance with regional data privacy standards like GDPR or UK data privacy laws.  
    
    Respond with concise, clear, and actionable advice tailored to the user's platform and privacy concerns.
    User Query: {query}"""
    return prompt

def get_prompt(query):
    prompt=f"""
    As an expert on UK cybersecurity laws and regulations, your role is to provide clear, accurate, and concise information. When asked, you should:  
    
    1. **Explain laws and regulations**: Provide details about the relevant UK legislation, such as the Computer Misuse Act 1990, the Data Protection Act 2018, and the UK General Data Protection Regulation (UK GDPR). Explain their purpose, scope, and key provisions.  
    2. **Detail punishments and penalties**: Clearly outline the legal consequences, fines, or imprisonment terms for offenses like unauthorized access, data breaches, or cyber fraud.  
    3. **Offer practical guidance**: Provide individuals or organizations with actionable advice to comply with the law, protect their systems, and report cybercrime.  
    4. **Cite credible sources**: Where appropriate, reference official government or legal resources like the National Cyber Security Centre (NCSC) or the UK Parliament website.  
    5. **Maintain neutrality and clarity**: Avoid legal jargon, and prioritize clarity and relevance to the query.  
    
    Here is the user question: {query}
        """
    return prompt


def get_data_privacy_prompt(privacy_policy):
    prompt=f"""
        **Instruction:**  
    Analyze the provided business data privacy policy and determine its compliance with the guidelines of UK and European data privacy laws, including GDPR.  
    
    **Steps:**  
    1. Identify areas where the policy aligns with UK and European data privacy laws.  
    2. Highlight sections that lack compliance or are unclear.  
    3. Provide detailed recommendations for improvement, citing specific legal guidelines (e.g., GDPR articles).  
    4. Give recommendations and integrate them into the policy and generate an updated version.  
    
    **Input:**  
    {privacy_policy}
    
    **Output:**  
    - **Compliance Report:**  
      - Aligned Sections: [List sections with detailed reasoning]  
      - Non-compliant Sections: [List issues with specific recommendations and legal references]  
    
    - **Recommendations:**  
      - [Detailed suggestions for each non-compliant section]  
    
    - **Revised Policy (if applicable):**  
      [Generate updated privacy policy text]  
        """
    return prompt

#############################################################################################################################################
colorama.init()
def type(words: str):
    for char in words:
        sleep(0.015)
        sys.stdout.write(char)
        sys.stdout.flush()
    # print()

url = r'https://www.virustotal.com/vtapi/v2/file/scan'
api= os.getenv("VT_API_KEY")
######################################################################################################################################





selection=st.sidebar.selectbox("Select",("Dashboard","NCA CrimeAssist","SafeSocial","Cyber Awareness Chatbot","Malicious File Scanner","Education Portal","PolicyGuardian","Feedback"))

if selection=="Dashboard":
    st.subheader("Welcome to Dashboard")
    sheet_name = 'Cyber Quiz (Responses)' # replace with your own sheet name
    sheet_id = '1QE9qW7DxaYp44RvTM0YUtpRFoe4GPt9i0WX-_OruXHM' # replace with your sheet's ID
    
    url=f"https://docs.google.com/spreadsheets/d/{sheet_id}/export?format=csv"
    df=pd.read_csv(url,names=["Timestamp","Q1","Q2"])
    # df.values
    # st.write(df.iloc[-1,1:].values)
    responses=df.iloc[-1,1:].values
    correct=[]
    # wrong=[]
    for i,j in zip(responses,["A", "A"]):
        if i==j:
            correct.append(1)
        else:
            correct.append(1)
    
    col1,col2,col3=st.columns(3)
    # st.write(correct)
    with col1:
        # Display pie chart
        fig, ax = plt.subplots(figsize=(5, 5))
        # sns.barplot(correct,ax=ax)
        ax.pie(correct, labels=["Correct","Wrong"], autopct="%1.1f%%", startangle=90)
        # ax.axis("equal")  # Equal aspect ratio ensures the pie is drawn as a circle.
        st.write("Cyber Fundamental Score")
        st.pyplot(fig)
        st.write("Improve your Score [Here](https://docs.google.com/forms/d/1u2Mm2gwvPQmMWRM_9WTtUC3-E_XRpX93ECFB8hQVMto/edit)")
    with col2:
        # Display pie chart
        fig, ax = plt.subplots(figsize=(5, 5))
        # sns.barplot(correct,ax=ax)
        ax.pie(correct, labels=["Correct","Wrong"], autopct="%1.1f%%", startangle=90)
        # ax.axis("equal")  # Equal aspect ratio ensures the pie is drawn as a circle.
        st.write("Risk Awareness Score")
        st.pyplot(fig)
        st.write("Improve your Score [Here](https://docs.google.com/forms/d/1otwGsbHuM9Ju_afEoOW6t__Z6dZ36HZmYJ7kHhi0on8/edit)")
    with col3:
        # Display pie chart
        fig, ax = plt.subplots(figsize=(5, 5))
        # sns.barplot(correct,ax=ax)
        ax.pie(correct, labels=["Correct","Wrong"], autopct="%1.1f%%", startangle=90)
        # ax.axis("equal")  # Equal aspect ratio ensures the pie is drawn as a circle.
        st.write("Cyber Awareness Score")
        st.pyplot(fig)
        st.write("Improve your Score [Here](https://docs.google.com/forms/d/1CAWF2l5TRPKMwVBMcjvxM2Hxo0rRreOTkQ7BD_j14ww/edit)")

    st.subheader("Cyber Security Guidelines")

    col1,col2,col3=st.columns(3)
    with col1:
        st.caption("Fundamentals")
        # st.write("The following list won’t indent no matter what I try:")
        st.markdown("- Educate yourself and enhance cyber knowlegdet")
        st.markdown("- Keep system software updated")
        st.markdown("- Use secure internet connections")
        st.markdown("- Secure web browsing and email")
        st.markdown("- Implement data retention, loss recovery capability")
        st.markdown("- Encrypt data and devices")
        st.markdown("- Secure devices that retain data")
        st.markdown("- Do not click on links you do not recognise.")
        st.markdown("- Protect your personal data.")
        st.markdown("- Be aware of where you are sending your data.")
        st.markdown("- Uninstall apps you are not using.")
        st.markdown("- Do not use public/free Wi-Fi – personal hotspots are safer.")
        st.markdown("- Use a strong, well-regarded browser. Google Chrome is the strongest in industry tests.")
        st.markdown("- Ensure that you only use apps from a reputable source.")
    with col2:
        st.caption("Essentials")
        # st.write("The following list won’t indent no matter what I try:")
        st.markdown("- Create complex passwords, protect passwords and change them regularly, do not reuse passwords across multiple systems and do not share passwords with colleagues.")
        st.markdown("- Use multi-factor authentication.")
        st.markdown("- Do not use public/free Wi-Fi – personal hotspots are safer.")
        st.markdown("- Use VPN and dongles (small, removable devices that have secure access to wireless broadband) when travelling.")
        st.markdown("- Put a Firewall")
        st.markdown("- Use Proxies")
        st.markdown("- Analyze Ads Carefully - Don't click it in exctiment")
        st.markdown("- Disable Multiple file downloads")
        st.markdown("- Don't Download Zipped/Compressed files")
        st.markdown("- Use Pen/USB drives carefully")
        st.markdown("- Regularly Scan your system for malwares")
        st.markdown("- Run Regular Data Backups")
        st.markdown("- Execute Automatic Security Updates")

    with col3:
        st.caption("Critical")
        # st.write("The following list won’t indent no matter what I try:")
        st.markdown("- Turn on your browser’s popup blocker. A popup blocker should be enabled at all times while browsing the internet.")
        st.markdown("- Do not use public phone chargers to avoid the risk of ‘juice jacking’.")
        st.markdown("- Check for ‘https:’ or a padlock icon on your browser’s URL bar to verify that a site is secure before entering any personal information.")
        st.markdown("- Understand the permissions you are granting to apps (eg, tracking your location and access to your contacts or camera).")
        st.markdown("- Report all phishing/spear phishing to the person designated to deal with cybersecurity concerns, even if the email is sent to your personal account rather than work.")
        st.markdown("- Uninstall apps you are not using.")
        st.markdown("- Do not use public/free Wi-Fi – personal hotspots are safer.")
        st.markdown("- Use VPN and dongles (small, removable devices that have secure access to wireless broadband) when travelling.")
        st.markdown("- Ensure that you only use apps from a reputable source.")
        st.markdown("- Limit login attempts")
    
    st.write("Latest Cyber Attacks")
    col1,col2,col3=st.columns(3)
    with col1:
        st.markdown('''
        <a href="https://www.securityweek.com/starbucks-grocery-stores-hit-by-blue-yonder-ransomware-attack/">
            <img src="https://www.securityweek.com/wp-content/uploads/2024/01/Supply-Chain-Software-Attack.jpg" width="500" height="200" />
        </a>''',
        unsafe_allow_html=True
        )
        st.caption("Starbucks, Grocery Stores Hit by Blue Yonder Ransomware Attack")
    with col2:
        st.markdown('''
        <a href="https://www.securityweek.com/hackers-stole-1-49-billion-in-cryptocurrency-to-date-in-2024/">
            <img src="https://www.securityweek.com/wp-content/uploads/2024/01/cryptocurrency.jpeg" width="500" height="200" />
        </a>''',
        unsafe_allow_html=True
        )
        st.caption("Hackers Stole $1.49 Billion in Cryptocurrency to Date in 2024")
    with col3:
        st.markdown('''
        <a href="https://www.securityweek.com/new-google-project-aims-to-become-global-clearinghouse-for-scam-fraud-data/">
            <img src="https://www.securityweek.com/wp-content/themes/zoxpress-child/assets/img/posts/security-week-post-0.jpg" width="500" height="200" />
        </a>''',
        unsafe_allow_html=True
        )
        st.caption("New Google Project Aims to Become Global Clearinghouse for Scam, Fraud Data")


##############################################################################################################################################
if selection=="NCA CrimeAssist":
    st.subheader("Welcome to National Crime Agency Crime Assistant")
    col1,col2=st.columns(2)
    with col1:
        st.html("<h4>Report an urgent crime</h4>")
        st.write("In an emergency always call 999")
    with col2:
        st.html("<h4>Report non-urgent crime</h4>")
        st.write("Please call your local police on 101")
    col1,col2=st.columns(2)
    with col1:
        st.html("<h4>Report a crime anonymously</h4>")
        st.write("You can also report crime anonymously to [Crimestoppers](https://crimestoppers-uk.org/give-information/forms/give-information-anonymously) online or by calling 0800 555 111")

    with col2:
        st.html("<h4>For General enquiries</h4>")
        st.write("Reach us via [email](communication@nca.gov.uk) or Telephone: 0370 496 7622 (available 24/7) not used for outgoing calls")
        
    
    st.html("<h4>Postal Address</h4>")
    st.write("PO Box 8000, London, SE11 5EN")

    st.html("<h4>Scam alert: fake letters and emails</h4>")
    st.write("Reach us via [email](report@phishing.gov.uk) or contact [Action Fraud](www.actionfraud.police.uk) /03001232040")

    st.subheader("Stay SAFE")
    st.write("Suspect anything or anyone you don’t know – no matter what or who they claim to be")
    st.write("Ask questions. Whatever a fraudster tries, you have the power to stay in control")
    st.write("Find out for certain who you are dealing with. Challenge anything that seems suspect")
    st.write("End a situation if you feel uncomfortable. If you feel threatened call your local police on 101 or 999")

    st.subheader("About")
    st.caption("The National Crime Agency (NCA) is a national law enforcement agency in the United Kingdom. It is the UK's lead agency against organised crime; human, weapon and drug trafficking; cybercrime; and economic crime that goes across regional and international borders, but it can be tasked to investigate any crime.")
    st.write("Visit Offical [NCA](https://www.nationalcrimeagency.gov.uk/) Website")

    st.subheader("Contact us at Social Media")
    social_media_links = [
        "https://web.facebook.com/sharer.php?u=https%3A%2F%2Fwww.nationalcrimeagency.gov.uk%2Fcontact-us&_rdc=1&_rdr#",
        "https://twitter.com/intent/tweet?text=https%3A%2F%2Fwww.nationalcrimeagency.gov.uk%2Fcontact-us"
    ]
    social_media_icons = SocialMediaIcons(social_media_links)
    social_media_icons.render()
##########################################################################################################################################
if selection=="SafeSocial":
    text=st.text_input("Put Concern Here")
    if st.button("Guide"):
        res=llm.invoke(get_sm_footprints_prompt(text))
        st.write(res.content)
 
#################################################################################################################################################


if selection=="Cyber Awareness Chatbot":
    st.subheader("Cyber Awareness Chatbot")
    query=st.text_input("Write Query Here")
    if st.button("Submit"):
        res=llm.invoke(get_prompt(query))
        st.write(res.content)

############################################################################################################################################################


def scan_file(api_key, file_path):
    url = 'https://www.virustotal.com/api/v3/files'
    headers = {
        'x-apikey': api_key
    }
    files = {
        'file': (file_path, open(file_path, 'rb'))
    }

    response = requests.post(url, headers=headers, files=files)
    
    if response.status_code == 200:
        result = response.json()
        # print("File uploaded successfully. Scan ID:", result['data']['id'])
        return result['data']['id']
    else:
        # print("Error:", response.status_code, response.text)
        return None

def get_file_scan_report(api_key, scan_id):
    url = f'https://www.virustotal.com/api/v3/analyses/{scan_id}'
    headers = {
        'x-apikey': api_key
    }

    response = requests.get(url, headers=headers)
    
    if response.status_code == 200:
        result = response.json()
        # print("Scan report retrieved successfully.")
        return result
    else:
        # print("Error:", response.status_code, response.text)
        return None

def scan_url(api_key, url):
    # Define the endpoint for URL scanning
    url_scan_endpoint = "https://www.virustotal.com/vtapi/v2/url/scan"
    
    # Define the parameters for the request
    params = {'apikey': api_key, 'url': url}
    
    # Make the request to VirusTotal
    response = requests.post(url_scan_endpoint, data=params)
    
    # Check if the request was successful
    if response.status_code == 200:
        result = response.json()
        return result.get('scan_id')
        # print("Scan ID:", result.get('scan_id'))
        # print("Verbose Message:", result.get('verbose_msg'))
    else:
        write("Error:", response.status_code, response.text)

def get_url_scan_report(api_key, scan_id):
    # Define the endpoint for retrieving scan reports
    url_report_endpoint = "https://www.virustotal.com/vtapi/v2/url/report"
    
    # Define the parameters for the request
    params = {'apikey': api_key, 'resource': scan_id}
    
    # Make the request to VirusTotal
    response = requests.get(url_report_endpoint, params=params)
    
    # Check if the request was successful
    if response.status_code == 200:
        result = response.json()
        return result
        # print("Scan Report:", result)
    else:
        st.write("Error:", response.status_code, response.text)

if selection=="Malicious File Scanner":
    selected_option=st.selectbox("Select",("File Scanner", "URL Scanner"))
    if selected_option=="File Scanner":
        st.subheader("Malicious File Scanner")
        file=st.file_uploader("Select a File")
        if file!=None and st.button("Analyze"): 
            scan_id = scan_file(api, file.name)
            report = get_file_scan_report(api, scan_id)
            st.write(report)
            
    if selected_option=="URL Scanner":
        st.subheader("Malicious URL Scanner")
        url=st.text_input("Paste URL Here")
        if st.button("Analyze") and url!=None:
            # Replace 'your_api_key' with your actual VirusTotal API key
            # api
            # api_key = '607c93270c569faf4f4de638f16e1e4747bd3d5e6b034368c862afe4a999e7e4'
            # url_to_scan = 'https://pypi.org/project/streamlit-extras/'
            scan_id=scan_url(api, url)
            st.write(get_url_scan_report(api, scan_id))

########################################################################################################################################################################################
if selection=="Education Portal":
    st.subheader("Welcome to Education Portal")

    st.write("")

    st.html(
    "<h4>Fundamentals</h4>")

    col1,col2=st.columns(2)
    with col1:
        st.caption("What is Cybercrime?")
        st.video("https://youtu.be/X7kFAy1E8Jw?si=lKWx-y3Tz1_dsSQP")
    with col2:
        st.caption("What is Cybersecurity?")
        st.video("https://youtu.be/Yr0xPVFcf-U?si=xNHedIZgSQbUc9f_")

    col1,col2=st.columns(2)
    with col1:
        st.caption("Malware and its types")
        st.video("https://youtu.be/n8mbzU0X2nQ?si=rqCjBFgrcmsj3WEw")
    with col2:
        st.caption("Tip for online data security")
        st.video("https://youtu.be/aO858HyFbKI?si=K7mDm_E4WysamUuK")
        
    with st.expander("More"):
        st.write("")

        col1,col2=st.columns(2)
        with col1:
            st.caption("How to Protect yourself against cybercrime?")
            st.video("https://youtu.be/EHqXMxY4_Nk?si=gyIz1gJhS2EfoHMr")
        with col2:
            st.caption("Why do cybercriminals want your computer?")
            st.video("https://youtu.be/NZ21QKzZtcI?si=rgaYN3mGvn-j-jT1")
        
        col1,col2=st.columns(2)
        with col1:
            st.caption("How to protect your accounts?")
            st.video("https://youtu.be/FuAs931mG08?si=hWlGuNgtkgGHryvn")
        with col2:
            st.caption("How you leak your data online?")
            st.video("https://youtu.be/Meh6NtQ-8iA?si=0eyMtMP-vo-IfgiQ")

        col1,col2=st.columns(2)
        with col1:
            st.caption("What is ransomware?")
            st.video("https://youtu.be/Vkjekr6jacg?si=NK_flkc0lXvLdQcy")
        with col2:
            st.caption("What is social engineering?")
            st.video("https://youtu.be/uvKTMgWRPw4?si=mCMtBaddyfM0OTU5")
    
        col1,col2=st.columns(2)
        with col1:
            st.caption("How to protect your privacy online?")
            st.video("https://youtu.be/JO55V34EnK8?si=4GKhg5ZxyHrYa21m")
        with col2:
            st.caption("How to protect your digital vallet?")
            st.video("https://youtu.be/2UMdkiXcMGU?si=1KUITh02f7AU8Ovr")
    
        col1,col2=st.columns(2)
        with col1:
            st.caption("How to configure privacy in Facebook?")
            st.video("https://youtu.be/ht9OmCJnxnA?si=JXf726uxyPtcU-qL")
        with col2:
            st.caption("How to configure privacy in Instagram?")
            st.video("https://youtu.be/ZcQzqdnkKvk?si=g5O2DzZG-Z4HNhCu")
    st.write("Test Yourself [Here](https://docs.google.com/forms/d/1u2Mm2gwvPQmMWRM_9WTtUC3-E_XRpX93ECFB8hQVMto/edit)")

    st.html("<h4>Essentials</h4>")

    col1,col2=st.columns(2)
    with col1:
        st.caption("How to create a strong password?")
        st.video("https://youtu.be/TvrFpAFitQ0?si=wiz21Gn_w94sH5F9")
    with col2:
        st.caption("What is Phishing?")
        st.video("https://youtu.be/00hpRjfbM0A?si=OiQ52JrL0qe6eJ6b")

    col1,col2=st.columns(2)
    with col1:
        st.caption("What is Spoofing and Indentity theft?")
        st.video("https://youtu.be/ULiinB6nMPw?si=7__iJrCQsN7CKsdm")
    with col2:
        st.caption("what is proxy server?")
        st.video("https://youtu.be/5cPIukqXe5w?si=djHvp2rs3GybcwWO")
    with st.expander("More"):
        st.write("")

        col1,col2=st.columns(2)
        with col1:
            st.caption("VPN Explained")
            st.video("https://youtu.be/R-JUOpCgTZc?si=AVQ0AVVWYpdJtP9E")
        with col2:
            st.caption("How Social Networks are  Security Risk?")
            st.video("https://youtu.be/IVgobw7JFeE?si=UGi6mA0Sat4ihMVY")

        col1,col2=st.columns(2)
        with col1:
            st.caption("What is firewall?")
            st.video("https://youtu.be/kDEX1HXybrU?si=WnoyRM9_98_MZ3zM")
        with col2:
            st.caption("Top 4 cyber fraud red flags")
            st.video("https://youtu.be/wHdLB_tHNVo?si=pLAehEzj4zzfZa4e")

        col1,col2=st.columns(2)
        with col1:
            
            st.caption("What is Zero day attack?")
            st.video("https://youtu.be/1wul_zBphpY?si=SmMaNlRvto-g_9tI")
        with col2:
            st.caption("Physical Security")
            st.video("https://youtu.be/tYapnGMrzp8?si=bPApRizw6lh4GJmy")

    st.write("Test Yourself [Here](https://docs.google.com/forms/d/1otwGsbHuM9Ju_afEoOW6t__Z6dZ36HZmYJ7kHhi0on8/edit)")
        
    st.html("<h4>Advanced</h4>")

    col1,col2=st.columns(2)
    with col1:
        st.caption("Different types of AI/ML-powered cybercrimes")
        st.video("https://youtu.be/1Z_dh9Xgtq0?si=DZq0Mg2yJM7SHgcJ")
    with col2:
        st.caption("How to respond to a network breach?")
        st.video("https://youtu.be/0_2P_trzFsQ?si=_iO2hdmGjMNN9iu0")

    col1,col2=st.columns(2)
    with col1:
        st.caption("Top 5 security checklist for IOT devices")
        st.video("https://youtu.be/-aV0ZCRq_0g?si=BFZS4wYZqJ4rlQRp")
    with col2:
        st.caption("How to do Secure remote working?")
        st.video("https://youtu.be/F-U_7CGYiHQ?si=6GWZp6RGeFkxeYaZ")
        
    with st.expander("More"):
        st.write("")

        col1,col2=st.columns(2)
        with col1:
            st.caption("Data privacy and GDPR")
            st.video("https://youtu.be/hk-ZgRIYYXc?si=QPGmg7l0eU6FPvoL")
        with col2:
            st.caption("Top 5 cloud security best practices checklist")
            st.video("https://youtu.be/ISkw0MwP2UA?si=AMiYkXKGdWTRc2zA")
    st.write("Test Yourself [Here](https://docs.google.com/forms/d/1CAWF2l5TRPKMwVBMcjvxM2Hxo0rRreOTkQ7BD_j14ww/edit)")
        
if selection=="PolicyGuardian":
    st.subheader("Welcome to Policy Guardian")
    text=st.text_area("Paste Policy Here")
    res=""
    if st.button("Analyze"):
        res=llm.invoke(get_data_privacy_prompt(text))
        st.write(res.content)
        res=res.content
    if res!="": 
        # Generate the Markdown file content
        file_name = "PolicyGuardian_response.md"
        markdown_content = f"# PolicyGuardian Response\n\n{res}"
        
        # Use Streamlit's `st.download_button` to allow downloading the file
        st.download_button(
            label="Download Markdown File",
            data=markdown_content,
            file_name=file_name,
            mime="text/markdown"
        )
        
######################################################################################################################################################################################################        
if selection=="Feedback":
    st.subheader("Welcome")
    st.caption("We'd love to hear your thoughts! Your feedback helps us improve and provide a better experience. Please share your thoughts below — it only takes a moment!")
    st.write("Leave Feedback [Here](https://docs.google.com/forms/d/e/1FAIpQLSfvDDT9ZQ8_QHRr6GS01SqsFajlJgQtlKMCXO82JPto6h4v8g/viewform?usp=sharing)")
