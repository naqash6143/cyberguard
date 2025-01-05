import streamlit as st
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
import plotly.graph_objects as go
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
from wordcloud import WordCloud
from dotenv import load_dotenv
# Load environment variables
load_dotenv()
import requests
import json
import sys
import os
import colorama

from time import sleep 
st.set_page_config(page_title="CyberGuard", page_icon="🔒", layout="centered", initial_sidebar_state="auto", menu_items=None)
##############################################################################################################################################################
st.title("💂‍♂️CYBER-GUARD")

#loader=PyPDFDirectoryLoader("./knowledgebase_for_chatbot/")
#data = loader.load()
#split the extracted data into text chunks using the text_splitter, which splits the text based on the specified number of characters and overlap
#text_splitter = RecursiveCharacterTextSplitter(chunk_size=1000, chunk_overlap=200)
#text_chunks = text_splitter.split_documents(data)

#download the embeddings to use to represent text chunks in a vector space, using the pre-trained model "sentence-transformers/all-MiniLM-L6-v2"
#embeddings = HuggingFaceEmbeddings(model_name="sentence-transformers/all-MiniLM-L6-v2")
# create embeddings for each text chunk using the FAISS class, which creates a vector index using FAISS and allows efficient searches between vectors
#vector_store = FAISS.from_documents(text_chunks, embedding=embeddings)

# Retrieve and generate using the relevant snippets of the blog.
#retriever = new_vector_store.as_retriever()
#prompt = hub.pull("rlm/rag-prompt")

# formatting the relevant chunks
#def format_docs(docs):
 #    return "\n\n".join(doc.page_content for doc in docs)
 
# from langchain_groq import ChatGroq
GROQ_API_KEY=os.getenv("GROQ_API_KEY")
llm = ChatGroq(
     temperature=0,
     model="llama-3.3-70b-versatile",
     api_key=GROQ_API_KEY
 )

#rag_chain = (
 #    {"context": retriever | format_docs, "question": RunnablePassthrough()}
  #   | prompt
   #  | llm
    # | StrOutputParser()
 #)





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

advanced_key = [ 
    "False videos or audio files created using advanced deep learning techniques", 
    "By encrypting sensitive user data", 
    "They predict defense strategies and exploit systems with new methods", 
    "Neural networks and Generative Adversarial Networks", 
    "Identifying the scope of the breach and indicators of compromise", 
    "Always using a VPN to access the internal network", 
    "Keeping personal data secure from unauthorized processing", 
    "Regularly patching cloud-based systems", 
    "Never trust, always verify user credibility", 
    "Understand the location and roles of OT devices"
]


####################################################
selection=st.sidebar.selectbox("Select",("Dashboard","NCA CrimeAssist","SafeSocial","Cyber Awareness Chatbot","Malicious File Scanner","Education Portal","PolicyGuardian","Feedback"))

if selection=="Dashboard":
    
    st.subheader("Welcome to Dashboard")
    #https://docs.google.com/spreadsheets/d/14KEJcHSMJf0qiXhSjUJpNdBWORHWUUpgQU-yLtp8xJI/edit?gid=27636577#gid=27636577   
    sheet_name = 'Cyber Quiz (Responses)' # replace with your own sheet name
    sheet_id = '14KEJcHSMJf0qiXhSjUJpNdBWORHWUUpgQU-yLtp8xJI' # replace with your sheet's ID
 
#https://docs.google.com/spreadsheets/d/14KEJcHSMJf0qiXhSjUJpNdBWORHWUUpgQU-yLtp8xJI/edit?gid=27636577#gid=27636577

#essential_key=["A combination of uppercase letters, lowercase letters, numbers, and symbols.","Deceptive Content","both types of cybercrime that involve the use of a fake identity to gain access to personal information","a computer or software system that acts as an intermediary between a user and the internet.","sleep problems, attention problems, and feelings of exclusion among teenagers.","97 zero-day vulnerabilities",
 
    url=f"https://docs.google.com/spreadsheets/d/{sheet_id}/export?format=csv"
    df=pd.read_csv(url)
    #st.write(df.iloc[-1,1:-1].values)
 
    # st.write(df.iloc[-1,1:].values)
    responses=df.iloc[-1,1:].values
    #st.write(responses)
    
    result=[]
    for i,j in zip(responses,advanced_key):
        if i==j:
            result.append(1)
        else:
            result.append(0)
    #st.write(correct)
    c=result.count(1)
    w=result.count(0)
 
    #st.write(list(set(correct)))
 
    col1,col2,col3=st.columns(3)
    # st.write(correct)
    with col1: 
        # Sample data
        labels = ['Correct', 'Incorrect']
        values = [c, w ]  # Example percentages or scores
        # Create a donut chart
        fig1 = go.Figure(data=[go.Pie(values=values, hole=0.7)])
        # Customize layout
        fig1.update_traces(
            hoverinfo='label+percent',
            #textinfo='value+percent',
            textfont_size=15,
            marker=dict(colors=['#FD8D3C','#6BAED6', '#74C476'], line=dict(color='#FFFFFF', width=2))
        )
        fig1.update_layout(title_text="yber Fundamental Score",width=300, height=300)
        st.plotly_chart(fig1)
        plt.show()
        if c<=3:
         st.write("&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;🙄")
        if c>3 and c<=8:
         st.write("&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;😊")
        if c==10:
         st.write("&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;😍")

     
     
     
     
     
     
     
     
     
     # Display pie chart
        #fig, ax = plt.subplots(figsize=(5, 5))
        # sns.barplot(result,ax=ax)
        #ax.pie(result, autopct="%1.1f%%", startangle=90)
        # ax.axis("equal")  # Equal aspect ratio ensures the pie is drawn as a circle.
        #st.write("Cyber Fundamental Score")
        #st.pyplot(fig)
        #st.write("🔥")
        st.write("Improve your Score [Here](https://docs.google.com/forms/d/e/1FAIpQLSe9__MDLd4zpgVskVXnjN2TxbWZgwxz5-Jtcq6YS_VCWfKAEg/viewform?usp=dialog)")
    with col2:
        
        
     
     
          
        # Sample data
        labels = ['Correct', 'Incorrect']
        values = [c, w ]  # Example percentages or scores
        
        # Create a donut chart
        fig2 = go.Figure(data=[go.Pie(values=values, hole=0.7)])
        
        # Customize layout
        fig2.update_traces(
            hoverinfo='label+percent',
            #textinfo='value+percent',
            textfont_size=15,
            marker=dict(colors=['#FD8D3C','#6BAED6', '#74C476'], line=dict(color='#FFFFFF', width=2))
        )
        fig2.update_layout(title_text="Cyber Essentials Score",width=302, height=302)
        st.plotly_chart(fig2)
        plt.show()
        if c<=3:
         st.write("&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;🙄")
        if c>3 and c<=8:
         st.write("&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;😊")
        if c==10:
         st.write("&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;😍")

     
     
     
     
     
     
     
     
     
     
     
     
        # Display pie chart
        #fig, ax = plt.subplots(figsize=(5, 5))
        # sns.barplot(result,ax=ax)
        #ax.pie(result,  autopct="%1.1f%%", startangle=90)
        # ax.axis("equal")  # Equal aspect ratio ensures the pie is drawn as a circle.
        #st.write("Cyber Essentials Score")
        #st.pyplot(fig)
        st.write("Improve your Score [Here](https://docs.google.com/forms/d/e/1FAIpQLSck_p-w_8cLQnIeU6IrHqoGZjcy8h_3taAOc083uhvw4l5kBA/viewform?usp=dialog)")
    with col3:
        
     
        # Sample data
        labels = ['Correct', 'Incorrect']
        values = [c, w ]  # Example percentages or scores
        
        # Create a donut chart
        fig = go.Figure(data=[go.Pie(values=values, hole=0.7)])
        
        # Customize layout
        fig.update_traces(
            hoverinfo='label+percent',
            #textinfo='value+percent',
            textfont_size=15,
            marker=dict(colors=['#FD8D3C','#6BAED6', '#74C476'], line=dict(color='#FFFFFF', width=2))
        )
        fig.update_layout(title_text="Cyber Advanced Score",width=301, height=301)
        st.plotly_chart(fig)
        #plt.show()
        if c<=3:
         st.write("&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;🙄")
        if c>3 and c<=8:
         st.write("&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;😊")
        if c==10:
         st.write("&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;😍")

     
     
     
     
     
     
     
     
     
     
     
     
     
     
        # Display pie chart
        #fig, ax = plt.subplots(figsize=(5, 5))
        # sns.barplot(correct,ax=ax)
        #ax.pie([c,w])
        # ax.axis("equal")  # Equal aspect ratio ensures the pie is drawn as a circle.
        #st.write("Cyber Advanced Score")
        #st.pyplot(fig)
        #if c<=3:
        # st.write("🙄")
        #if c>3 and c<=8:
        # st.write("😋")
        #if c==10:
        # st.write("😍")
         
         #st.button(":thumbsup:")

        st.write("Improve your Score [Here](https://docs.google.com/forms/d/e/1FAIpQLSd_xz8xAvkVodtLzBqmXyWZBT50-W0VnFllFFyg-DePVuh8ww/viewform)")
    st.subheader("Cyber Security Guidelines")
    
    col1,col2,col3=st.columns(3)
    with col1:
        st.caption("Fundamentals")
        # st.write("The following list won’t indent no matter what I try:")
        st.markdown("✅ Educate yourself and enhance cyber knowlegde")
        st.markdown("✅ Keep system software updated")
        st.markdown("✅ Use secure internet connections")
        st.markdown("✅ Secure web browsing and email")
        st.markdown("✅ Implement data retention, loss recovery capability")
        st.markdown("✅ Encrypt data and devices")
        st.markdown("✅ Secure devices that retain data")
        st.markdown("✅ Do not click on links you do not recognise.")
        st.markdown("✅ Protect your personal data.")
        st.markdown("✅ Be aware of where you are sending your data.")
        st.markdown("✅ Uninstall apps you are not using.")
        st.markdown("✅ Do not use public/free Wi-Fi – personal hotspots are safer.")
        st.markdown("✅ Use a strong, well-regarded browser. Google Chrome is the strongest in industry tests.")
        st.markdown("✅ Ensure that you only use apps from a reputable source.")
    with col2:
        st.caption("Essentials")
        # st.write("The following list won’t indent no matter what I try:")
        st.markdown("✅ Create complex passwords, protect passwords and change them regularly, do not reuse passwords across multiple systems and do not share passwords with colleagues.")
        st.markdown("✅ Use multi-factor authentication.")
        st.markdown("✅ Do not use public/free Wi-Fi – personal hotspots are safer.")
        st.markdown("✅ Use VPN and dongles (small, removable devices that have secure access to wireless broadband) when travelling.")
        st.markdown("✅ Put a Firewall")
        st.markdown("✅ Use Proxies")
        st.markdown("✅ Analyze Ads Carefully - Don't click it in exctiment")
        st.markdown("✅ Disable Multiple file downloads")
        st.markdown("✅ Don't Download Zipped/Compressed files")
        st.markdown("✅ Use Pen/USB drives carefully")
        st.markdown("✅ Regularly Scan your system for malwares")
        st.markdown("✅ Run Regular Data Backups")
        st.markdown("✅ Execute Automatic Security Updates")

    with col3:
        st.caption("Critical")
        # st.write("The following list won’t indent no matter what I try:")
        st.markdown("✅ Turn on your browser’s popup blocker. A popup blocker should be enabled at all times while browsing the internet.")
        st.markdown("✅ Do not use public phone chargers to avoid the risk of ‘juice jacking’.")
        st.markdown("✅ Check for ‘https:’ or a padlock icon on your browser’s URL bar to verify that a site is secure before entering any personal information.")
        st.markdown("✅ Understand the permissions you are granting to apps (eg, tracking your location and access to your contacts or camera).")
        st.markdown("✅ Report all phishing/spear phishing to the person designated to deal with cybersecurity concerns, even if the email is sent to your personal account rather than work.")
        st.markdown("✅ Uninstall apps you are not using.")
        st.markdown("✅ Do not use public/free Wi-Fi – personal hotspots are safer.")
        st.markdown("✅ Use VPN and dongles (small, removable devices that have secure access to wireless broadband) when travelling.")
        st.markdown("✅ Ensure that you only use apps from a reputable source.")
        st.markdown("✅ Limit login attempts")
    
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
    st.subheader("Welcome to National Crime Agency Crime Assistant 👮‍♂️")
    col1,col2=st.columns(2)
    with col1:
        st.html("<h4>Report an urgent crime</h4>")
        st.write("In an emergency always 📱call 999")
    with col2:
        st.html("<h4>Report non-urgent crime</h4>")
        st.write("Please 📱 call your local police on 101")
    col1,col2=st.columns(2)
    with col1:
        st.html("<h4>Report a crime anonymously</h4>")
        st.write("You can also report crime anonymously to [Crimestoppers](https://crimestoppers-uk.org/give-information/forms/give-information-anonymously) online or by calling 0800 555 111")

    with col2:
        st.html("<h4>For General enquiries</h4>")
        st.write("Reach us via [📧](communication@nca.gov.uk) or Telephone 📱: 0370 496 7622 (available 24/7) not used for outgoing calls")
        
    
    st.html("<h4>📮 Postal Address</h4>")
    st.write("PO Box 8000, London, SE11 5EN")

    st.html("<h4>Scam alert: fake letters and emails</h4>")
    st.write("Reach us via [📧](report@phishing.gov.uk) or contact [Action Fraud](🌐www.actionfraud.police.uk) /03001232040")

    st.subheader("Stay SAFE")
    st.write("Suspect anything or anyone you don’t know – no matter what or who they claim to be")
    st.write("Ask questions. Whatever a fraudster tries, you have the power to stay in control")
    st.write("Find out for certain who you are dealing with. Challenge anything that seems suspect")
    st.write("End a situation if you feel uncomfortable. If you feel threatened call your local police on 101 or 999")

    st.subheader("About")
    st.caption("The National Crime Agency (NCA) is a national law enforcement agency in the United Kingdom. It is the UK's lead agency against organised crime; human, weapon and drug trafficking; cybercrime; and economic crime that goes across regional and international borders, but it can be tasked to investigate any crime.")
    st.write("Visit Offical [NCA](🌐https://www.nationalcrimeagency.gov.uk/) Website")

    st.subheader("Contact us at Social Media")
    social_media_links = [
        "https://web.facebook.com/sharer.php?u=https%3A%2F%2Fwww.nationalcrimeagency.gov.uk%2Fcontact-us&_rdc=1&_rdr#",
        "https://twitter.com/intent/tweet?text=https%3A%2F%2Fwww.nationalcrimeagency.gov.uk%2Fcontact-us"
    ]
    social_media_icons = SocialMediaIcons(social_media_links)
    social_media_icons.render()
##########################################################################################################################################
if selection=="SafeSocial":
    st.subheader("Safe Your Social Identity 📋")
    text=st.text_input("Put Concern Here")
    if st.button("Guide"):
        res=llm.invoke(get_sm_footprints_prompt(text))
        st.write(res.content)
 
#################################################################################################################################################


if selection=="Cyber Awareness Chatbot":
    st.subheader("Cyber Awareness Chatbot 🤖")
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
        st.subheader("Malicious File Scanner 🕵️‍♂️")
        file=st.file_uploader("Select a File")
        if file!=None and st.button("Analyze"): 
            scan_id = scan_file(api, file.name)
            report = get_file_scan_report(api, scan_id)
            st.write(report)
            
    if selected_option=="URL Scanner":
        st.subheader("Malicious URL Scanner 🕵️‍♂️")
        url=st.text_input("Paste URL Here")
        if st.button("Analyze") and url!=None:
            scan_id=scan_url(api, url)
            st.write(get_url_scan_report(api, scan_id))

########################################################################################################################################################################################
if selection=="Education Portal":
    st.subheader("Welcome to Education Portal 🏫")
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
    st.subheader("Welcome to Policy Guardian 🧾")
    text=st.text_area("Paste Policy Here")
    res=""
    if st.button("Analyze 🔍") and text!="":
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


text="The Dashboard is intuitive and provides a comprehensive overview of cybersecurity scores. Great job!SafeSocial’s guidelines for deleting traces of activity are practical and very helpful for social media users.The Cyber Awareness module is very informative but could include more interactive content for better engagement.NCA CrimeAssist is a thoughtful addition, offering clear instructions on how to report cybercrimes.The Malicious File Scanner integrated with VirusTotal is a great tool for analyzing risks.Policy Guardian is excellent for businesses looking to stay compliant with GDPR. The recommendations are spot on.The Education Portal offers a wide range of resources, but adding quizzes could enhance the learning experience.Cyber Security Guidelines are well-structured and provide essential tips for all levels of users.Including recent articles from SecurityWeek is a brilliant idea for keeping users updated.SafeSocial’s focus on GDPR compliance is highly relevant and much needed in today’s environment.The Cyber Awareness Chatbot effectively simplifies complex legal concepts for users.Adding a feature to track progress in the Education Portal could make it more engaging.The Dashboard’s personalized recommendations are very insightful and practical.The Stay SAFE tips in NCA CrimeAssist are simple yet powerful in promoting safety practices.Malicious File Scanner provides detailed reports, making it easy to understand potential threats.Policy Guardian’s ability to uncover conflicts with regulations is highly beneficial for compliance.The Cyber Awareness module could be improved with more country-specific legal guidelines.SafeSocial is an excellent tool for enhancing social media security awareness.The Education Portal covers a wide range of topics, but some videos are too lengthy.The Dashboard’s friendly welcome message makes the platform feel approachable.Adding more cybersecurity tips to the Cyber Security Guidelines could enhance its value.The integration of VirusTotal in the Malicious File Scanner is a smart move for enhanced security.Policy Guardian’s tailored recommendations are highly appreciated by businesses.The Dashboard could benefit from a dark mode option for better usability.The Stay SAFE banner in NCA CrimeAssist is a clever way to educate users about safety practices.The Education Portal’s segmentation into Basic, Standard, and Professional levels is very effective.Policy Guardian provides a great framework for organizations to strengthen their policies.The Cyber Awareness module could use more real-life examples of legal violations.SafeSocial’s guidance on data sharing regulations is very relevant and well-explained.The Malicious URL Scanner’s reports are detailed and easy to interpret.Including cybersecurity quizzes in the Education Portal would be a nice addition.The Cyber Awareness Chatbot simplifies complex legalities in a user-friendly way.Policy Guardian offers clear and actionable recommendations for regulatory compliance.SafeSocial could include more region-specific guidelines for social media security.The Dashboard’s Cyber Fundamental Score is a unique and useful feature.NCA CrimeAssist could include a direct reporting feature for non-emergency incidents.The Malicious File Scanner is a must-have tool for detecting threats effectively.The Education Portal’s Advanced section is a great resource for professionals.Adding a glossary to the Cyber Awareness module could enhance user understanding.SafeSocial empowers users to take control of their social media security.Policy Guardian’s insights into GDPR compliance are invaluable for businesses.The Cyber Awareness Chatbot could offer more region-specific legal information.The Dashboard is user-friendly and provides meaningful insights into cybersecurity.Including additional security tools in the Cyber Security Guidelines would be helpful.The Malicious URL Scanner is a great addition for identifying unsafe links.Policy Guardian’s ability to tailor recommendations to specific needs is commendable.The Education Portal could include certifications for completing modules.The Cyber Awareness module is a valuable resource for understanding cybersecurity laws.SafeSocial’s focus on GDPR compliance is very timely and relevant.NCA CrimeAssist’s Stay SAFE banner is simple yet effective.The Malicious File Scanner could include a feature to schedule regular scans.The Dashboard’s personalized guidance is a standout feature.The Education Portal’s variety of resources caters to a wide audience.Policy Guardian’s insights into data protection are invaluable.The Cyber Awareness Chatbot could benefit from integrating more interactive elements.The Dashboard’s Cyber Awareness Score is a great metric for self-assessment.SafeSocial’s detailed guidelines are a must-read for all social media users.NCA CrimeAssist provides a comprehensive guide to handling cybercrimes effectively.The Malicious File Scanner’s reports are detailed and easy to understand.Policy Guardian is a fantastic tool for ensuring GDPR compliance in organizations.The Education Portal could include gamified elements to make learning more engaging.CyberGuard’s Dashboard is incredibly intuitive, offering users a quick overview of their cybersecurity score, while the detailed breakdown of vulnerabilities ensures even non-technical users can understand their risk levels. The personalized recommendations based on the score make it even more actionable.SafeSocial is an essential tool for anyone using social media. Its detailed guidance on privacy settings across multiple platforms and specific tips on GDPR compliance show a thoughtful approach to user safety.The Education Portal is a goldmine of resources. The categorized content for beginners, professionals, and advanced users ensures that everyone finds value. Adding interactive modules like quizzes and simulations could enhance engagement further.NCA CrimeAssist is an excellent feature. It not only provides clear steps to report cybercrimes but also includes real-life examples of what constitutes a cybercrime, making it easier for users to understand when to take action.The integration of the Malicious File Scanner with VirusTotal is a game-changer. The ability to analyze both known and unknown threats with detailed reports builds confidence in users. Scheduling scans would make it even better.Policy Guardian’s tailored recommendations for GDPR compliance are spot-on. The inclusion of conflict detection within policies makes it invaluable for businesses looking to avoid fines or audits.The Cyber Awareness Chatbot is a standout feature. Its ability to simplify complex cybersecurity and legal topics into conversational language makes it accessible to all users. Adding a voice-based interaction option could elevate its usability.The Dashboard’s ability to provide real-time alerts for vulnerabilities combined with the Cyber Awareness module’s detailed explanations makes it a comprehensive tool for proactive cybersecurity management.SafeSocial goes beyond just recommending better privacy settings. Its feature to analyze user behavior and provide warnings about overexposed personal information on platforms like Facebook or Instagram is exceptional.The Education Portal’s modular design makes learning cybersecurity concepts easy. The inclusion of video tutorials, case studies, and reading material ensures a holistic learning experience. Certifications on course completion would be a valuable addition.Policy Guardian is an impressive addition to the CyberGuard suite. Its step-by-step approach to reviewing and optimizing business policies for compliance with cybersecurity standards is highly practical.The Dashboard and Malicious File Scanner together provide a robust safety net for users. The real-time alerts from the Dashboard and the in-depth threat analysis of files make it hard for malicious entities to slip through.NCA CrimeAssist offers a wide range of resources, from identifying phishing scams to reporting cyberstalking. The feature to directly connect to local cybercrime authorities is a thoughtful addition.The Education Portal’s Basic to Professional pathway is well-structured, allowing users to build a solid foundation before tackling more advanced topics. Including webinars from cybersecurity experts could enhance its value.SafeSocial’s emphasis on GDPR compliance and detailed walkthroughs for managing privacy on platforms like LinkedIn and TikTok demonstrate its commitment to comprehensive user safety.The Dashboard’s Cyber Fundamental Score is not just a number; the accompanying breakdown and personalized improvement tips make it an actionable metric. Pairing this with automated reminders for updates would be a great enhancement.The Malicious File Scanner is one of the best I’ve used. Its integration with multiple databases ensures thorough analysis. Adding cloud storage scanning capabilities would make it even more versatile.Policy Guardian provides an unmatched level of detail when reviewing organizational policies. Its ability to map policies to international standards like ISO 27001 ensures global applicability.The Cyber Awareness Chatbot is more than just a Q&A tool. It proactively identifies gaps in user knowledge and offers tailored resources, making it feel like a personal tutor.The Education Portal is a treasure trove for cybersecurity enthusiasts. From interactive lessons to downloadable cheat sheets, it covers all bases. Adding a feedback section for users to suggest topics would enhance it further.SafeSocial is a lifesaver for social media users. Its guidance on creating stronger passwords, identifying phishing attempts, and spotting fraudulent messages is highly actionable.The Malicious File Scanner and Dashboard work seamlessly together. Being alerted to vulnerabilities and then scanning files for threats makes it easy to address issues proactively.NCA CrimeAssist’s inclusion of Stay SAFE guidelines is brilliant. It’s simple, actionable, and ensures users can take immediate steps to improve their safety online.Policy Guardian has set a new standard for compliance tools. Its ability to detect overlapping or conflicting policies within an organization is unique and highly beneficial.The Education Portal’s gamification elements, like badges and progress tracking, make learning cybersecurity concepts engaging. Expanding the quiz library with scenario-based questions would be a nice addition.SafeSocial stands out for its ability to analyze not just user settings but also activity patterns to highlight potential risks. Adding an AI-based risk prediction model could make it even more powerful.The Cyber Awareness Chatbot is surprisingly effective at explaining complex regulations like GDPR in simple terms. Offering downloadable summaries of conversations would be a helpful feature.NCA CrimeAssist is a comprehensive resource for users who may feel overwhelmed after a cybercrime incident. The clear instructions and emotional support resources make it a standout feature.The Malicious File Scanner is incredibly fast and thorough. The detailed breakdown of threats, including severity and potential actions, makes it highly user-friendly.Policy Guardian’s focus on GDPR compliance is unparalleled. Its checklist format for ensuring compliance with specific data protection rules is easy to follow and highly effective.The Dashboard and Cyber Awareness Chatbot complement each other well. While the Dashboard provides real-time insights, the Chatbot helps users understand the implications of those insights.SafeSocial’s emphasis on educating users about the risks of overexposure on social media, combined with actionable tips, makes it a must-have tool in today’s digital age.The Education Portal’s extensive library of resources is impressive. Including expert interviews or podcasts could add another layer of depth to the content.NCA CrimeAssist’s focus on helping users recognize different types of cybercrimes is commendable. The feature to generate a report draft for law enforcement could be an excellent addition.The Dashboard’s Cyber Fundamental Score offers not only a snapshot of current security levels but also actionable recommendations to address weak areas. Including peer benchmarks could make it even more insightful.The Malicious File Scanner’s ability to scan files from cloud storage providers like Google Drive or Dropbox would make it even more versatile.Policy Guardian is a lifesaver for businesses. Its integration with legal databases to ensure compliance with international standards makes it a critical tool for any organization."

sentiment={'positive': 45, 'neutral': 10, 'negative': 5}
emotions={'satisfaction': 20, 'frustration': 3, 'excitement': 5, 'trust': 10}
themes={'ease_of_use': 10, 'innovation': 8, 'technical_challenges': 2}
user_activity= {'Dashboard':17,'SafeSocial':13,'PolicyGuardian':12,'Education Portal':12,'NCA Crime Assist':8,'Malicious File/URL Scanner':9,'Cyber Awareness Chatbot':7}
recommendations={'improvement_suggestions': {'Dashboard': ['adding automated reminders for updates', 'including peer benchmarks for the Cyber Fundamental Score'], 'SafeSocial': ['adding an AI-based risk prediction model', 'including more cybersecurity tips to the Cyber Security Guidelines'], 'Policy Guardian': ['including certifications for completing modules', 'expanding the quiz library with scenario-based questions'], 'Education Portal': ['adding interactive modules like quizzes and simulations', 'including gamified elements to make learning more engaging'], 'NCA CrimeAssist': ['including a direct reporting feature for non-emergency incidents', 'generating a report draft for law enforcement'], 'Malicious File Scanner': ['adding a feature to schedule regular scans', 'including cloud storage scanning capabilities'], 'Cyber Awareness Chatbot': ['adding a voice-based interaction option', 'offering downloadable summaries of conversations']}, 'innovation_opportunities': ['integrating AI-based risk prediction models', 'developing gamified cybersecurity training programs', 'creating a community forum for users to share best practices and ask questions']}

if selection=="Feedback":
    st.subheader("Welcome to User Feedback Section📝")
    st.caption("We'd love to hear your thoughts! Your feedback helps us improve and provide a better experience. Please share your thoughts below — it only takes a moment!")
    st.write("Leave Feedback [Here](https://docs.google.com/forms/d/e/1FAIpQLSfvDDT9ZQ8_QHRr6GS01SqsFajlJgQtlKMCXO82JPto6h4v8g/viewform?usp=sharing)")

    st.subheader("User Feedback on CyberGuard")

    col1,col2=st.columns(2)
    with col1:    
      # Display pie chart
      fig, ax = plt.subplots(figsize=(5, 5))
      x=[i for i in sentiment.keys()]
      y=[i for i in sentiment.values()]
      ax.pie(y, labels=x, autopct="%1.1f%%", startangle=90)
      # ax.axis("equal")  # Equal aspect ratio ensures the pie is drawn as a circle.
      st.write("Sentiment Analysis")
      st.pyplot(fig)
    with col2:

      # Display pie chart
      fig, ax = plt.subplots(figsize=(5, 5))
      x=[i for i in emotions.keys()]
      y=[i for i in emotions.values()]
      ax.pie(y, labels=x, autopct="%1.1f%%", startangle=90)
      # ax.axis("equal")  # Equal aspect ratio ensures the pie is drawn as a circle.
      st.write("Emotion Analysis")
      st.pyplot(fig)
    
    col1,col2=st.columns(2)
    with col1:
      # Create a bar plot
      fig, ax = plt.subplots()
      x=[i for i in themes.keys()]
      y=[i for i in themes.values()]
      ax.barh(x,y)
      # Adding title and labels
      ax.set_title('Themes Analysis')
      ax.set_xlabel('Categories')
      ax.set_ylabel('Values')
      # Rotate x-axis labels by 45 degrees
      plt.xticks(rotation=45)
      # Display the plot in Streamlit
      st.pyplot(fig)

    with col2:

     # Generate the word cloud
      wordcloud = WordCloud(width=800, height=400, background_color='white').generate(text)
      # Display the word cloud using matplotlib
      plt.figure(figsize=(10, 5))
      plt.imshow(wordcloud, interpolation='bilinear')
      plt.axis('off')  # Hide axes
      plt.title("Wordcloud for CyberGuard Reviews")
      st.pyplot(plt)

    col1,col2=st.columns(2)
    with col1:
      # Create a bar plot
      fig, ax = plt.subplots()
      x=[i for i in user_activity.keys()]
      y=[i for i in user_activity.values()]
      ax.barh(x,y)
      # Adding title and labels
      ax.set_title('User Activity on the CyberGuard')
      ax.set_xlabel('Module')
      ax.set_ylabel('Values')
      # Rotate x-axis labels by 45 degrees
      plt.xticks(rotation=90)
      # Display the plot in Streamlit
      st.pyplot(fig)

    with col2:
      st.write("")
    st.subheader("Recommendations for each Module")
    col1,col2,col3=st.columns(3)
    with col1:
      st.write("Dashboard")
      st.write(recommendations['improvement_suggestions']['Dashboard'])
    with col2:
      st.write("SafeSocial")
      st.write(recommendations['improvement_suggestions']['SafeSocial'])
    with col3:
      st.write("Policy Guardian")
      st.write(recommendations['improvement_suggestions']['Policy Guardian'])
    col1,col2,col3=st.columns(3)
    with col1:
      st.write("Education Portal")
      st.write(recommendations['improvement_suggestions']['Education Portal'])
    with col2:
      st.write("NCA CrimeAssist")
      st.write(recommendations['improvement_suggestions']['NCA CrimeAssist'])
    with col3:
      st.write("Malicious File Scanner")
      st.write(recommendations['improvement_suggestions']['Malicious File Scanner'])
    col1,col2,col3=st.columns(3)
    with col1:
      st.write("Cyber Awareness Chatbot")
      st.write(recommendations['improvement_suggestions']['Cyber Awareness Chatbot'])
      

